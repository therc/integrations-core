# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
from __future__ import division

from collections import defaultdict
from contextlib import closing

import pyhdb
from six import iteritems
from six.moves import zip

from datadog_checks.base import AgentCheck, is_affirmative
from datadog_checks.base.utils.containers import iter_unique

from . import queries


class SapHanaCheck(AgentCheck):
    __NAMESPACE__ = 'sap_hana'
    SERVICE_CHECK_CONNECT = 'can_connect'
    SERVICE_CHECK_STATUS = 'status'

    def __init__(self, name, init_config, instances):
        super(SapHanaCheck, self).__init__(name, init_config, instances)

        self._server = self.instance.get('server', '')
        self._port = self.instance.get('port', 39015)
        self._username = self.instance.get('username', '')
        self._password = self.instance.get('password', '')
        self._timeout = float(self.instance.get('timeout', 10))
        self._row_limit = int(self.instance.get('row_limit', 1000))
        self._tags = self.instance.get('tags', [])

        # Add server & port tags
        self._tags.append('server:{}'.format(self._server))
        self._tags.append('port:{}'.format(self._port))

        custom_queries = self.instance.get('custom_queries', [])
        use_global_custom_queries = self.instance.get('use_global_custom_queries', True)

        # Handle overrides
        if use_global_custom_queries == 'extend':
            custom_queries.extend(self.init_config.get('global_custom_queries', []))
        elif 'global_custom_queries' in self.init_config and is_affirmative(use_global_custom_queries):
            custom_queries = self.init_config.get('global_custom_queries', [])

        # Deduplicate
        self._custom_queries = list(iter_unique(custom_queries))

        # We'll connect on the first check run
        self._conn = None

        # Whether or not to use the hostnames contained in the queried tables
        self._use_hana_hostnames = is_affirmative(self.instance.get('use_hana_hostnames', True))

        # Save master database hostname to act as the default if `use_hana_hostnames` is true
        self._master_hostname = None

    def check(self, instance):
        if self._conn is None:
            connection = self.get_connection()
            if connection is None:
                return

            self._conn = connection

        for query_method in (
            self.query_master_database,
            self.query_database_status,
            self.query_backup_status,
            self.query_licenses,
            self.query_connection_overview,
            self.query_disk_usage,
            self.query_service_memory,
            self.query_service_component_memory,
            self.query_row_store_memory,
        ):
            try:
                query_method()
            except Exception as e:
                error = str(e)
                if 'insufficient privilege' in error:
                    error += ' ---> Access to the following views is required: {}'.format(', '.join(queries.VIEWS_USED))

                self.log.error('Error running `%s`: %s', query_method.__name__, error)
                continue

    def query_master_database(self):
        # https://help.sap.com/viewer/4fe29514fd584807ac9f2a04f6754767/2.0.02/en-US/20ae63aa7519101496f6b832ec86afbd.html
        # Only 1 database
        for master in self.iter_rows(queries.MasterDatabase):
            tags = ['db:{}'.format(master['db_name']), 'usage:{}'.format(master['usage'])]
            tags.extend(self._tags)

            master_hostname = master['host']
            if self._use_hana_hostnames:
                self._master_hostname = master_hostname

            self.gauge(
                'uptime',
                (master['current_time'] - master['start_time']).total_seconds(),
                tags=tags,
                hostname=self.get_hana_hostname(master_hostname),
            )

    def query_database_status(self):
        # https://help.sap.com/viewer/4fe29514fd584807ac9f2a04f6754767/2.0.02/en-US/dbbdc0d96675470e80801c5ddfb8d348.html
        for status in self.iter_rows(queries.SystemDatabases):
            tags = ['db:{}'.format(status['db_name'])]
            tags.extend(self._tags)

            db_status = self.OK if status['status'].lower() == 'yes' else self.CRITICAL
            message = status['details'] or None
            self.service_check(
                self.SERVICE_CHECK_STATUS, db_status, message=message, tags=tags, hostname=self.get_hana_hostname()
            )

    def query_backup_status(self):
        # https://help.sap.com/viewer/4fe29514fd584807ac9f2a04f6754767/2.0.02/en-US/783108ba8b8b4c709959220b4535a010.html
        for backup in self.iter_rows(queries.GlobalSystemBackupProgress):
            tags = [
                'db:{}'.format(backup['db_name']),
                'service_name:{}'.format(backup['service']),
                'status:{}'.format(backup['status']),
            ]
            tags.extend(self._tags)

            seconds_since_last_backup = (backup['current_time'] - backup['end_time']).total_seconds()
            self.gauge(
                'backup.latest', seconds_since_last_backup, tags=tags, hostname=self.get_hana_hostname(backup['host'])
            )

    def query_licenses(self):
        # https://help.sap.com/viewer/4fe29514fd584807ac9f2a04f6754767/2.0.02/en-US/1d7e7f52f6574a238c137e17b0840673.html
        for hana_license in self.iter_rows(queries.GlobalSystemLicenses):
            tags = ['sid:{}'.format(hana_license['sid']), 'product_name:{}'.format(hana_license['product_name'])]
            tags.extend(self._tags)

            host = self.get_hana_hostname()

            if hana_license['expiration_date']:
                expiration = (hana_license['expiration_date'] - hana_license['start_date']).total_seconds()
            else:
                expiration = -1
            self.gauge('license.expiration', expiration, tags=tags, hostname=host)

            total = hana_license['limit']
            self.gauge('license.size', total, tags=tags, hostname=host)

            used = hana_license['usage']
            self.gauge('license.usage', used, tags=tags, hostname=host)

            usable = total - used
            self.gauge('license.usable', usable, tags=tags, hostname=host)

            if total:
                utilized = used / total * 100
            else:
                utilized = 0
            self.gauge('license.utilized', utilized, tags=tags, hostname=host)

    def query_connection_overview(self):
        # https://help.sap.com/viewer/4fe29514fd584807ac9f2a04f6754767/2.0.02/en-US/20abcf1f75191014a254a82b3d0f66bf.html
        db_counts = defaultdict(lambda: {'running': 0, 'idle': 0})
        for conn in self.iter_rows(queries.GlobalSystemConnectionsStatus):
            db_counts[(conn['db_name'], conn['host'], conn['port'])][conn['status'].lower()] += conn['total']

        for (db, host, port), counts in iteritems(db_counts):
            tags = ['db:{}'.format(db), 'hana_port:{}'.format(port)]
            tags.extend(self._tags)

            host = self.get_hana_hostname(host)
            running = counts['running']
            idle = counts['idle']

            self.gauge('connection.running', running, tags=tags, hostname=host)
            self.gauge('connection.idle', idle, tags=tags, hostname=host)
            self.gauge('connection.active', running + idle, tags=tags, hostname=host)

    def query_disk_usage(self):
        # https://help.sap.com/viewer/4fe29514fd584807ac9f2a04f6754767/2.0.02/en-US/a2aac2ee72b341699fa8eb3988d8cecb.html
        for disk in self.iter_rows(queries.GlobalSystemDiskUsage):
            tags = ['db:{}'.format(disk['db_name']), 'disk_resource:{}'.format(disk['resource'])]
            tags.extend(self._tags)

            host = self.get_hana_hostname(disk['host'])

            total = disk['total']
            self.gauge('disk.size', total, tags=tags, hostname=host)

            used = max(0, disk['used'])
            self.gauge('disk.used', used, tags=tags, hostname=host)

            usable = total - used
            self.gauge('disk.usable', usable, tags=tags, hostname=host)

            if total:
                utilized = used / total * 100
            else:
                utilized = 0
            self.gauge('disk.utilized', utilized, tags=tags, hostname=host)

    def query_service_memory(self):
        # https://help.sap.com/viewer/4fe29514fd584807ac9f2a04f6754767/2.0.02/en-US/20bf33c975191014bc16d7ffb7717db2.html
        for memory in self.iter_rows(queries.GlobalSystemServiceMemory):
            tags = [
                'db:{}'.format(memory['db_name'] or 'none'),
                'hana_port:{}'.format(memory['port']),
                'service_name:{}'.format(memory['service']),
            ]
            tags.extend(self._tags)

            host = self.get_hana_hostname(memory['host'])

            # Overall
            self.gauge('memory.service.overall.physical.total', memory['physical'], tags=tags, hostname=host)
            self.gauge('memory.service.overall.virtual.total', memory['virtual'], tags=tags, hostname=host)

            total = memory['total']
            self.gauge('memory.service.overall.total', total, tags=tags, hostname=host)

            used = memory['used']
            self.gauge('memory.service.overall.used', used, tags=tags, hostname=host)

            usable = total - used
            self.gauge('memory.service.overall.usable', usable, tags=tags, hostname=host)

            if total:
                utilized = used / total * 100
            else:
                utilized = 0
            self.gauge('memory.service.overall.utilized', utilized, tags=tags, hostname=host)

            # Heap
            heap_total = memory['heap_total']
            self.gauge('memory.service.heap.total', heap_total, tags=tags, hostname=host)

            heap_used = memory['heap_used']
            self.gauge('memory.service.heap.used', heap_used, tags=tags, hostname=host)

            heap_usable = heap_total - heap_used
            self.gauge('memory.service.heap.usable', heap_usable, tags=tags, hostname=host)

            if heap_total:
                heap_utilized = heap_used / heap_total * 100
            else:
                heap_utilized = 0
            self.gauge('memory.service.heap.utilized', heap_utilized, tags=tags, hostname=host)

            # Shared
            shared_total = memory['shared_total']
            self.gauge('memory.service.shared.total', shared_total, tags=tags, hostname=host)

            shared_used = memory['shared_used']
            self.gauge('memory.service.shared.used', shared_used, tags=tags, hostname=host)

            shared_usable = shared_total - shared_used
            self.gauge('memory.service.shared.usable', shared_usable, tags=tags, hostname=host)

            if shared_total:
                shared_utilized = shared_used / shared_total * 100
            else:
                shared_utilized = 0
            self.gauge('memory.service.shared.utilized', shared_utilized, tags=tags, hostname=host)

            # Compactors
            compactors_total = memory['compactors_total']
            self.gauge('memory.service.compactor.total', compactors_total, tags=tags, hostname=host)

            compactors_usable = memory['compactors_usable']
            self.gauge('memory.service.compactor.usable', compactors_usable, tags=tags, hostname=host)

            compactors_used = compactors_total - compactors_usable
            self.gauge('memory.service.compactor.used', compactors_used, tags=tags, hostname=host)

            if compactors_total:
                compactors_utilized = compactors_used / compactors_total * 100
            else:
                compactors_utilized = 0
            self.gauge('memory.service.compactor.utilized', compactors_utilized, tags=tags, hostname=host)

    def query_service_component_memory(self):
        # https://help.sap.com/viewer/4fe29514fd584807ac9f2a04f6754767/2.0.02/en-US/20bed4f675191014a4cf8e62c28d16ae.html
        for memory in self.iter_rows(queries.GlobalSystemServiceComponentMemory):
            tags = [
                'db:{}'.format(memory['db_name'] or 'none'),
                'hana_port:{}'.format(memory['port']),
                'component_name:{}'.format(memory['component']),
            ]
            tags.extend(self._tags)

            self.gauge(
                'memory.service.component.used',
                memory['used'],
                tags=tags,
                hostname=self.get_hana_hostname(memory['host']),
            )

    def query_row_store_memory(self):
        # https://help.sap.com/viewer/4fe29514fd584807ac9f2a04f6754767/2.0.02/en-US/20bb47a975191014b1e2f6bd0a685d7b.html
        for memory in self.iter_rows(queries.GlobalSystemRowStoreMemory):
            tags = [
                'db:{}'.format(memory['db_name']),
                'hana_port:{}'.format(memory['port']),
                'category_name:{}'.format(memory['category']),
            ]
            tags.extend(self._tags)

            host = self.get_hana_hostname(memory['host'])

            total = memory['total']
            self.gauge('memory.row_store.total', total, tags=tags, hostname=host)

            used = memory['used']
            self.gauge('memory.row_store.used', used, tags=tags, hostname=host)

            usable = memory['usable']
            self.gauge('memory.row_store.usable', usable, tags=tags, hostname=host)

            if total:
                utilized = used / total * 100
            else:
                utilized = 0
            self.gauge('memory.row_store.utilized', utilized, tags=tags, hostname=host)

    def iter_rows(self, query):
        # https://github.com/SAP/PyHDB
        with closing(self._conn.cursor()) as cursor:
            cursor.execute(query.query)

            # Re-use column access map for efficiency
            result = {}

            rows = cursor.fetchmany(self._row_limit)
            while rows:
                for row in rows:
                    for column, value in zip(query.fields, row):
                        result[column] = value

                    yield result

                # Get next result set, if any
                rows = cursor.fetchmany(self._row_limit)

    def get_connection(self):
        try:
            connection = pyhdb.connection.Connection(
                host=self._server, port=self._port, user=self._username, password=self._password, timeout=self._timeout
            )
            connection.connect()
        except Exception as e:
            error = str(e).replace(self._password, '*' * len(self._password))
            self.log.error('Unable to connect to SAP HANA: {}'.format(error))
            self.service_check(self.SERVICE_CHECK_CONNECT, self.CRITICAL, message=error, tags=self._tags)
        else:
            self.service_check(self.SERVICE_CHECK_CONNECT, self.OK, tags=self._tags)
            return connection

    def get_hana_hostname(self, hostname=None):
        if self._use_hana_hostnames:
            return hostname or self._master_hostname
