# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)


def spec_validator(spec, loader):
    if not isinstance(spec, dict):
        loader.errors.append('{}: Configuration specifications must be a mapping object'.format(loader.integration))
        return

    if 'files' not in spec:
        loader.errors.append(
            '{}: Configuration specifications must contain a top-level `files` attribute'.format(loader.integration)
        )
        return

    files = spec['files']
    if not isinstance(files, list):
        loader.errors.append('{}: The top-level `files` attribute must be an array'.format(loader.integration))
        return

    files_validator(files, loader)


def files_validator(files, loader):
    file_names_origin = {}
    example_file_names_origin = {}
    for file_index, config_file in enumerate(files, 1):
        if not isinstance(config_file, dict):
            loader.errors.append(
                '{}, file #{}: File attribute must be a mapping object'.format(loader.integration, file_index)
            )
            continue

        if 'name' not in config_file:
            loader.errors.append(
                '{}, file #{}: Every file must contain a `name` attribute representing the '
                'final destination the Agent loads'.format(loader.integration, file_index)
            )
            continue

        file_name = config_file['name']
        if not isinstance(file_name, str):
            loader.errors.append(
                '{}, file #{}: Attribute `name` must be a string'.format(loader.integration, file_index)
            )

        if file_name in file_names_origin:
            loader.errors.append(
                '{}, file #{}: File name `{}` already used by file #{}'.format(
                    loader.integration, file_index, file_name, file_names_origin[file_name]
                )
            )
        else:
            file_names_origin[file_name] = file_index

        if file_name == 'auto_conf.yaml':
            if 'example_name' in config_file and config_file['example_name'] != file_name:
                loader.errors.append(
                    '{}, file #{}: Example file name `{}` should be `{}`'.format(
                        loader.integration, file_index, config_file['example_name'], file_name
                    )
                )

            example_file_name = config_file.setdefault('example_name', file_name)
        else:
            expected_name = '{}.yaml'.format(loader.integration or 'conf')
            if file_name != expected_name:
                loader.errors.append(
                    '{}, file #{}: File name `{}` should be `{}`'.format(
                        loader.integration, file_index, file_name, expected_name
                    )
                )

            example_file_name = config_file.setdefault('example_name', 'conf.yaml.example')

        if not isinstance(example_file_name, str):
            loader.errors.append(
                '{}, file #{}: Attribute `example_name` must be a string'.format(loader.integration, file_index)
            )

        if example_file_name in example_file_names_origin:
            loader.errors.append(
                '{}, file #{}: Example file name `{}` already used by file #{}'.format(
                    loader.integration, file_index, example_file_name, example_file_names_origin[example_file_name]
                )
            )
        else:
            example_file_names_origin[example_file_name] = file_index

        if 'sections' not in config_file:
            loader.errors.append(
                '{}, {}: Every file must contain a `sections` attribute containing things like '
                '`init_config`, `instances`, etc.'.format(loader.integration, file_name)
            )
            continue

        sections = config_file['sections']
        if not isinstance(sections, list):
            loader.errors.append(
                '{}, {}: The `sections` attribute must be an array'.format(loader.integration, file_name)
            )
            continue

        sections_validator(sections, loader, file_name)


def sections_validator(sections, loader, file_name):
    section_names_origin = {}
    for section_index, section in enumerate(sections, 1):
        if not isinstance(section, dict):
            loader.errors.append(
                '{}, {}, section #{}: Section attribute must be a mapping object'.format(
                    loader.integration, file_name, section_index
                )
            )
            continue

        if 'name' not in section:
            loader.errors.append(
                '{}, {}, section #{}: Every section must contain a `name` attribute representing the top-level '
                'keys such as `instances` or `logs`'.format(loader.integration, file_name, section_index)
            )
            continue

        section_name = section['name']
        if not isinstance(section_name, str):
            loader.errors.append(
                '{}, {}, section #{}: Attribute `name` must be a string'.format(
                    loader.integration, file_name, section_index
                )
            )

        if section_name in section_names_origin:
            loader.errors.append(
                '{}, {}, section #{}: Section name `{}` already used by section #{}'.format(
                    loader.integration, file_name, section_index, section_name, section_names_origin[section_name]
                )
            )
        else:
            section_names_origin[section_name] = section_index

        if 'options' not in section:
            section['options'] = []
            continue

        options = section['options']
        if not isinstance(options, list):
            loader.errors.append(
                '{}, {}, {}: The `options` attribute must be an array'.format(
                    loader.integration, file_name, section_name
                )
            )
            continue

        options_validator(options, loader, file_name, section_name)


def options_validator(options, loader, file_name, section_name):
    option_names_origin = {}
    for option_index, option in enumerate(options, 1):
        if not isinstance(option, dict):
            loader.errors.append(
                '{}, {}, {}, option #{}: Option attribute must be a mapping object'.format(
                    loader.integration, file_name, section_name, option_index
                )
            )
            continue

        if 'name' not in option:
            loader.errors.append(
                '{}, {}, {}, option #{}: Every option must contain a `name` attribute'.format(
                    loader.integration, file_name, section_name, option_index
                )
            )
            continue

        option_name = option['name']
        if not isinstance(option_name, str):
            loader.errors.append(
                '{}, {}, {}, option #{}: Attribute `name` must be a string'.format(
                    loader.integration, file_name, section_name, option_index
                )
            )

        if option_name in option_names_origin:
            loader.errors.append(
                '{}, {}, {}, option #{}: Option name `{}` already used by option #{}'.format(
                    loader.integration,
                    file_name,
                    section_name,
                    option_index,
                    option_name,
                    option_names_origin[option_name],
                )
            )
        else:
            option_names_origin[option_name] = option_index

        if 'description' not in option:
            loader.errors.append(
                '{}, {}, {}, {}: Every option must contain a `description` attribute'.format(
                    loader.integration, file_name, section_name, option_name
                )
            )
            continue

        description = option['description']
        if not isinstance(description, str):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `description` must be a string'.format(
                    loader.integration, file_name, section_name, option_name, description
                )
            )

        option.setdefault('required', False)
        if not isinstance(option['required'], bool):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `required` must be true or false'.format(
                    loader.integration, file_name, section_name, option_name
                )
            )

        option.setdefault('secret', False)
        if not isinstance(option['secret'], bool):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `secret` must be true or false'.format(
                    loader.integration, file_name, section_name, option_name
                )
            )

        if 'value' not in option:
            loader.errors.append(
                '{}, {}, {}, {}: Every option must contain a `value` attribute'.format(
                    loader.integration, file_name, section_name, option_name
                )
            )
            continue

        value = option['value']
        if not isinstance(value, dict):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `value` must be a mapping object'.format(
                    loader.integration, file_name, section_name, option_name
                )
            )
            continue

        value_validator(value, loader, file_name, section_name, option_name, depth=0)


def value_validator(value, loader, file_name, section_name, option_name, depth=0):
    if 'type' not in value:
        loader.errors.append(
            '{}, {}, {}, {}: Every value must contain a `type` attribute'.format(
                loader.integration, file_name, section_name, option_name
            )
        )
        return

    value_type = value['type']
    if not isinstance(value_type, str):
        loader.errors.append(
            '{}, {}, {}, {}: Attribute `type` must be a string'.format(
                loader.integration, file_name, section_name, option_name
            )
        )
        return

    if value_type == 'string':
        if 'example' not in value:
            if not depth:
                value['example'] = '<{}>'.format(option_name.upper())
        elif not isinstance(value['example'], str):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `example` for `type` {} must be a string'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )

        if 'pattern' in value and not isinstance(value['pattern'], str):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `pattern` for `type` {} must be a string'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )
    elif value_type in ('integer', 'number'):
        if 'example' not in value:
            if not depth:
                value['example'] = '<{}>'.format(option_name.upper())
        elif not isinstance(value['example'], (int, float)):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `example` for `type` {} must be a number'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )

        minimum_valid = True
        maximum_valid = True

        if 'minimum' in value and not isinstance(value['minimum'], (int, float)):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `minimum` for `type` {} must be a number'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )
            minimum_valid = False

        if 'maximum' in value and not isinstance(value['maximum'], (int, float)):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `maximum` for `type` {} must be a number'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )
            maximum_valid = False

        if (
            'minimum' in value
            and 'maximum' in value
            and minimum_valid
            and maximum_valid
            and value['maximum'] <= value['minimum']
        ):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `maximum` for `type` {} must be greater than attribute `minimum`'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )
    elif value_type == 'boolean':
        if 'example' not in value:
            if not depth:
                loader.errors.append(
                    '{}, {}, {}, {}: Every {} must contain a default `example` attribute'.format(
                        loader.integration, file_name, section_name, option_name, value_type
                    )
                )
        elif not isinstance(value['example'], bool):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `example` for `type` {} must be true or false'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )
    elif value_type == 'array':
        if 'example' not in value:
            if not depth:
                value['example'] = []
        elif not isinstance(value['example'], list):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `example` for `type` {} must be an array'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )

        if 'uniqueItems' in value and not isinstance(value['uniqueItems'], bool):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `uniqueItems` for `type` {} must be true or false'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )

        min_items_valid = True
        max_items_valid = True

        if 'minItems' in value and not isinstance(value['minItems'], int):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `minItems` for `type` {} must be an integer'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )
            min_items_valid = False

        if 'maxItems' in value and not isinstance(value['maxItems'], int):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `maxItems` for `type` {} must be an integer'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )
            max_items_valid = False

        if (
            'minItems' in value
            and 'maxItems' in value
            and min_items_valid
            and max_items_valid
            and value['maxItems'] <= value['minItems']
        ):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `maxItems` for `type` {} must be greater than attribute `minItems`'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )

        if 'items' not in value:
            loader.errors.append(
                '{}, {}, {}, {}: Every {} must contain an `items` attribute'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )
            return

        items = value['items']
        if not isinstance(items, dict):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `items` for `type` {} must be a mapping object'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )
            return

        value_validator(items, loader, file_name, section_name, option_name, depth=depth + 1)
    elif value_type == 'object':
        if 'example' not in value:
            if not depth:
                value['example'] = {}
        elif not isinstance(value['example'], dict):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `example` for `type` {} must be a mapping object'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )

        required = value.get('required')
        if 'required' in value:
            if not isinstance(required, list):
                loader.errors.append(
                    '{}, {}, {}, {}: Attribute `required` for `type` {} must be an array'.format(
                        loader.integration, file_name, section_name, option_name, value_type
                    )
                )
                required = None
            elif not required:
                loader.errors.append(
                    '{}, {}, {}, {}: Remove attribute `required` for `type` {} if no properties are required'.format(
                        loader.integration, file_name, section_name, option_name, value_type
                    )
                )
            elif len(required) - len(set(required)):
                loader.errors.append(
                    '{}, {}, {}, {}: All entries in attribute `required` for `type` {} must be unique'.format(
                        loader.integration, file_name, section_name, option_name, value_type
                    )
                )

        properties = value.setdefault('properties', [])
        if not isinstance(properties, list):
            loader.errors.append(
                '{}, {}, {}, {}: Attribute `properties` for `type` {} must be an array'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )
            return

        new_depth = depth + 1
        property_names = []
        for prop in properties:
            if not isinstance(prop, dict):
                loader.errors.append(
                    '{}, {}, {}, {}: Every entry in `properties` for `type` {} must be a mapping object'.format(
                        loader.integration, file_name, section_name, option_name, value_type
                    )
                )

            if 'name' not in prop:
                loader.errors.append(
                    '{}, {}, {}, {}: Every entry in `properties` for `type` {} must contain a `name` attribute'.format(
                        loader.integration, file_name, section_name, option_name, value_type
                    )
                )
                continue

            name = prop['name']
            if not isinstance(name, str):
                loader.errors.append(
                    '{}, {}, {}, {}: Attribute `name` for `type` {} must be a string'.format(
                        loader.integration, file_name, section_name, option_name, value_type
                    )
                )
                continue

            property_names.append(name)

            value_validator(prop, loader, file_name, section_name, option_name, depth=new_depth)

        if len(property_names) - len(set(property_names)):
            loader.errors.append(
                '{}, {}, {}, {}: All entries in attribute `properties` for `type` {} must have unique names'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )

        if required and set(required).difference(property_names):
            loader.errors.append(
                '{}, {}, {}, {}: All entries in attribute `required` for `type` '
                '{} must be defined in the`properties` attribute'.format(
                    loader.integration, file_name, section_name, option_name, value_type
                )
            )
    else:
        loader.errors.append(
            '{}, {}, {}, {}: Unknown type `{}`'.format(
                loader.integration, file_name, section_name, option_name, value_type
            )
        )
