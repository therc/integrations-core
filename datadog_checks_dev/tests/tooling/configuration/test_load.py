# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
import pytest

from .utils import get_spec

pytestmark = pytest.mark.conf


def test_cache():
    spec = get_spec('')
    spec.data = 'test'
    spec.load()
    spec.load()

    assert spec.data == 'test'


def test_invalid_yaml():
    spec = get_spec(
        """
        foo:
          - bar
          baz: oops
        """
    )
    spec.load()

    assert spec.errors[0].startswith('test: Unable to parse the configuration specification')


def test_not_map():
    spec = get_spec('- foo')
    spec.load()

    assert 'test: Configuration specifications must be a mapping object' in spec.errors


def test_no_files():
    spec = get_spec(
        """
        foo:
        - bar
        """
    )
    spec.load()

    assert 'test: Configuration specifications must contain a top-level `files` attribute' in spec.errors


def test_files_not_array():
    spec = get_spec(
        """
        files:
          foo: bar
        """
    )
    spec.load()

    assert 'test: The top-level `files` attribute must be an array' in spec.errors


def test_file_not_map():
    spec = get_spec(
        """
        files:
        - 5
        - baz
        """
    )
    spec.load()

    assert 'test, file #1: File attribute must be a mapping object' in spec.errors
    assert 'test, file #2: File attribute must be a mapping object' in spec.errors


def test_file_no_name():
    spec = get_spec(
        """
        files:
        - foo: bar
        """
    )
    spec.load()

    assert (
        'test, file #1: Every file must contain a `name` attribute representing the final destination the Agent loads'
    ) in spec.errors


def test_file_name_duplicate():
    spec = get_spec(
        """
        files:
        - name: test.yaml
        - name: test.yaml
        """
    )
    spec.load()

    assert 'test, file #2: File name `test.yaml` already used by file #1' in spec.errors


def test_example_file_name_duplicate():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
        - name: bar.yaml
          example_name: test.yaml.example
        """
    )
    spec.load()

    assert 'test, file #2: Example file name `test.yaml.example` already used by file #1' in spec.errors


def test_file_name_not_string():
    spec = get_spec(
        """
        files:
        - name: 123
          example_name: test.yaml.example
        """
    )
    spec.load()

    assert 'test, file #1: Attribute `name` must be a string' in spec.errors


def test_example_file_name_not_string():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: 123
        """
    )
    spec.load()

    assert 'test, file #1: Attribute `example_name` must be a string' in spec.errors


def test_file_name_standard_incorrect():
    spec = get_spec(
        """
        files:
        - name: foo.yaml
        """
    )
    spec.load()

    assert 'test, file #1: File name `foo.yaml` should be `test.yaml`' in spec.errors


def test_example_file_name_autodiscovery_incorrect():
    spec = get_spec(
        """
        files:
        - name: auto_conf.yaml
          example_name: test.yaml.example
        """
    )
    spec.load()

    assert 'test, file #1: Example file name `test.yaml.example` should be `auto_conf.yaml`' in spec.errors


def test_example_file_name_standard_default():
    spec = get_spec(
        """
        files:
        - name: test.yaml
        """
    )
    spec.load()

    assert spec.data['files'][0]['example_name'] == 'conf.yaml.example'


def test_example_file_name_autodiscovery_default():
    spec = get_spec(
        """
        files:
        - name: auto_conf.yaml
        """
    )
    spec.load()

    assert spec.data['files'][0]['example_name'] == 'auto_conf.yaml'


def test_no_sections():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
        """
    )
    spec.load()

    assert (
        'test, test.yaml: Every file must contain a `sections` attribute '
        'containing things like `init_config`, `instances`, etc.'
    ) in spec.errors


def test_sections_not_array():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
            foo: bar
        """
    )
    spec.load()

    assert 'test, test.yaml: The `sections` attribute must be an array' in spec.errors


def test_section_not_map():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - 5
          - baz
        """
    )
    spec.load()

    assert 'test, test.yaml, section #1: Section attribute must be a mapping object' in spec.errors
    assert 'test, test.yaml, section #2: Section attribute must be a mapping object' in spec.errors


def test_section_no_name():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - foo: bar
        """
    )
    spec.load()

    assert (
        'test, test.yaml, section #1: Every section must contain a `name` attribute '
        'representing the top-level keys such as `instances` or `logs`'
    ) in spec.errors


def test_section_name_not_string():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: 123
        """
    )
    spec.load()

    assert 'test, test.yaml, section #1: Attribute `name` must be a string' in spec.errors


def test_section_name_duplicate():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
          - name: instances
        """
    )
    spec.load()

    assert 'test, test.yaml, section #2: Section name `instances` already used by section #1' in spec.errors


def test_no_options():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
        """
    )
    spec.load()

    assert not spec.errors
    assert spec.data['files'][0]['sections'][0]['options'] == []


def test_options_not_array():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
              foo: bar
        """
    )
    spec.load()

    assert 'test, test.yaml, instances: The `options` attribute must be an array' in spec.errors


def test_option_not_map():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - 5
            - baz
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, option #1: Option attribute must be a mapping object' in spec.errors
    assert 'test, test.yaml, instances, option #2: Option attribute must be a mapping object' in spec.errors


def test_option_no_name():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - foo: bar
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, option #1: Every option must contain a `name` attribute' in spec.errors


def test_option_name_not_string():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: 123
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, option #1: Attribute `name` must be a string' in spec.errors


def test_option_name_duplicate():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: server
            - name: server
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, option #2: Option name `server` already used by option #1' in spec.errors


def test_option_no_description():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Every option must contain a `description` attribute' in spec.errors


def test_option_description_not_string():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: 123
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `description` must be a string' in spec.errors


def test_option_required_not_boolean():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              required: nope
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `required` must be true or false' in spec.errors


def test_option_required_default():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
        """
    )
    spec.load()

    assert spec.data['files'][0]['sections'][0]['options'][0]['required'] is False


def test_option_secret_not_boolean():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              secret: nope
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `secret` must be true or false' in spec.errors


def test_option_secret_default():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
        """
    )
    spec.load()

    assert spec.data['files'][0]['sections'][0]['options'][0]['secret'] is False


def test_option_no_value():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Every option must contain a `value` attribute' in spec.errors


def test_option_value_not_map():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
              - foo
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `value` must be a mapping object' in spec.errors


def test_value_no_type():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                foo: bar
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Every value must contain a `type` attribute' in spec.errors


def test_value_type_string_valid_basic():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: string
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_not_string():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: 123
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `type` must be a string' in spec.errors


def test_value_type_string_example_default_no_depth():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: string
        """
    )
    spec.load()

    assert spec.data['files'][0]['sections'][0]['options'][0]['value']['example'] == '<FOO>'


def test_value_type_string_example_default_nested():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: string
        """
    )
    spec.load()

    assert not spec.errors
    assert 'example' not in spec.data['files'][0]['sections'][0]['options'][0]['value']['items']


def test_value_type_string_example_not_string():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: string
                example: 123
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `example` for `type` string must be a string' in spec.errors


def test_value_type_string_example_valid():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: string
                example: bar
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_string_pattern_not_string():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: string
                pattern: 123
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `pattern` for `type` string must be a string' in spec.errors


def test_value_type_integer_valid_basic():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: integer
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_integer_example_default_no_depth():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: integer
        """
    )
    spec.load()

    assert spec.data['files'][0]['sections'][0]['options'][0]['value']['example'] == '<FOO>'


def test_value_type_integer_example_default_nested():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: integer
        """
    )
    spec.load()

    assert not spec.errors
    assert 'example' not in spec.data['files'][0]['sections'][0]['options'][0]['value']['items']


def test_value_type_integer_example_not_number():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: integer
                example: bar
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `example` for `type` integer must be a number' in spec.errors


def test_value_type_integer_example_valid():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: integer
                example: 5
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_integer_correct_minimum():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: integer
                minimum: 5
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_integer_incorrect_minimum():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: integer
                minimum: "5"
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `minimum` for `type` integer must be a number' in spec.errors


def test_value_type_integer_correct_maximum():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: integer
                maximum: 5
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_integer_incorrect_maximum():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: integer
                maximum: "5"
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `maximum` for `type` integer must be a number' in spec.errors


def test_value_type_integer_correct_minimum_maximum():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: integer
                minimum: 4
                maximum: 5
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_integer_incorrect_minimum_maximum():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: integer
                minimum: 5
                maximum: 5
        """
    )
    spec.load()

    assert (
        'test, test.yaml, instances, foo: Attribute `maximum` for '
        '`type` integer must be greater than attribute `minimum`'
    ) in spec.errors


def test_value_type_number_valid_basic():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: number
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_number_example_default_no_depth():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: number
        """
    )
    spec.load()

    assert spec.data['files'][0]['sections'][0]['options'][0]['value']['example'] == '<FOO>'


def test_value_type_number_example_default_nested():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: number
        """
    )
    spec.load()

    assert not spec.errors
    assert 'example' not in spec.data['files'][0]['sections'][0]['options'][0]['value']['items']


def test_value_type_number_example_not_number():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: number
                example: bar
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `example` for `type` number must be a number' in spec.errors


def test_value_type_number_example_valid():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: number
                example: 5
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_number_correct_minimum():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: number
                minimum: 5
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_number_incorrect_minimum():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: number
                minimum: "5"
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `minimum` for `type` number must be a number' in spec.errors


def test_value_type_number_correct_maximum():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: number
                maximum: 5
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_number_incorrect_maximum():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: number
                maximum: "5"
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `maximum` for `type` number must be a number' in spec.errors


def test_value_type_number_correct_minimum_maximum():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: number
                minimum: 4
                maximum: 5
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_number_incorrect_minimum_maximum():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: number
                minimum: 5
                maximum: 5
        """
    )
    spec.load()

    assert (
        'test, test.yaml, instances, foo: Attribute `maximum` for '
        '`type` number must be greater than attribute `minimum`'
    ) in spec.errors


def test_value_type_boolean_example_default_no_depth():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: boolean
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Every boolean must contain a default `example` attribute' in spec.errors


def test_value_type_boolean_example_default_nested():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: boolean
        """
    )
    spec.load()

    assert not spec.errors
    assert 'example' not in spec.data['files'][0]['sections'][0]['options'][0]['value']['items']


def test_value_type_boolean_example_not_boolean():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: boolean
                example: "true"
        """
    )
    spec.load()

    assert (
        'test, test.yaml, instances, foo: Attribute `example` for `type` boolean must be true or false'
    ) in spec.errors


def test_value_type_boolean_example_valid():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: boolean
                example: true
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_array_example_default_no_depth():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: string
        """
    )
    spec.load()

    assert spec.data['files'][0]['sections'][0]['options'][0]['value']['example'] == []


def test_value_type_array_example_default_nested():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: array
                  items:
                    type: string
        """
    )
    spec.load()

    assert not spec.errors
    assert 'example' not in spec.data['files'][0]['sections'][0]['options'][0]['value']['items']


def test_value_type_array_example_not_array():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                example: 123
                items:
                  type: string
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `example` for `type` array must be an array' in spec.errors


def test_value_type_array_example_valid():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                example:
                - foo
                - bar
                items:
                  type: string
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_array_no_items():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Every array must contain an `items` attribute' in spec.errors


def test_value_type_array_items_not_array():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items: 123
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `items` for `type` array must be a mapping object' in spec.errors


def test_value_type_array_unique_items_not_boolean():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: string
                uniqueItems: yup
        """
    )
    spec.load()

    assert (
        'test, test.yaml, instances, foo: Attribute `uniqueItems` for `type` array must be true or false'
    ) in spec.errors


def test_value_type_array_correct_min_items():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: string
                minItems: 5
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_array_incorrect_min_items():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: string
                minItems: 5.5
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `minItems` for `type` array must be an integer' in spec.errors


def test_value_type_array_correct_max_items():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: string
                maxItems: 5
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_array_incorrect_max_items():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: string
                maxItems: 5.5
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `maxItems` for `type` array must be an integer' in spec.errors


def test_value_type_array_correct_min_items_max_items():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: string
                minItems: 4
                maxItems: 5
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_array_incorrect_min_items_max_items():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: array
                items:
                  type: string
                minItems: 5
                maxItems: 5
        """
    )
    spec.load()

    assert (
        'test, test.yaml, instances, foo: Attribute `maxItems` for '
        '`type` array must be greater than attribute `minItems`'
    ) in spec.errors


def test_value_type_object_example_default_no_depth():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
        """
    )
    spec.load()

    assert not spec.errors
    assert spec.data['files'][0]['sections'][0]['options'][0]['value']['example'] == {}


def test_value_type_object_example_default_nested():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: array
                items:
                  type: object
        """
    )
    spec.load()

    assert not spec.errors
    assert 'example' not in spec.data['files'][0]['sections'][0]['options'][0]['value']['items']


def test_value_type_object_example_not_map():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
                example: 123
        """
    )
    spec.load()

    assert (
        'test, test.yaml, instances, foo: Attribute `example` for `type` object must be a mapping object'
    ) in spec.errors


def test_value_type_object_example_valid():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
                example:
                  foo: bar
                items:
                  type: string
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_object_required_not_array():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
                required: {}
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `required` for `type` object must be an array' in spec.errors


def test_value_type_object_required_empty():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
                required: []
        """
    )
    spec.load()

    assert (
        'test, test.yaml, instances, foo: Remove attribute `required` for `type` object if no properties are required'
    ) in spec.errors


def test_value_type_object_required_not_unique():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
                required:
                - foo
                - foo
        """
    )
    spec.load()

    assert (
        'test, test.yaml, instances, foo: All entries in attribute `required` for `type` object must be unique'
    ) in spec.errors


def test_value_type_object_properties_default():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
        """
    )
    spec.load()

    assert not spec.errors
    assert spec.data['files'][0]['sections'][0]['options'][0]['value']['properties'] == []


def test_value_type_object_properties_not_array():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
                properties: {}
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `properties` for `type` object must be an array' in spec.errors


def test_value_type_object_properties_entry_not_map():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
                properties:
                - foo
        """
    )
    spec.load()

    assert (
        'test, test.yaml, instances, foo: Every entry in `properties` for `type` object must be a mapping object'
    ) in spec.errors


def test_value_type_object_properties_entry_no_name():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
                properties:
                - type: string
        """
    )
    spec.load()

    assert (
        'test, test.yaml, instances, foo: Every entry in `properties` for `type` object must contain a `name` attribute'
    ) in spec.errors


def test_value_type_object_properties_entry_name_not_string():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
                properties:
                - name: 123
                  type: string
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Attribute `name` for `type` object must be a string' in spec.errors


def test_value_type_object_properties_valid():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
                properties:
                - name: bar
                  type: string
        """
    )
    spec.load()

    assert not spec.errors


def test_value_type_object_properties_entry_name_not_unique():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
                properties:
                - name: bar
                  type: string
                - name: bar
                  type: string
        """
    )
    spec.load()

    assert (
        'test, test.yaml, instances, foo: All entries in attribute '
        '`properties` for `type` object must have unique names'
    ) in spec.errors


def test_value_type_object_properties_required_not_met():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: object
                properties:
                - name: bar
                  type: string
                required:
                - foo
                - bar
        """
    )
    spec.load()

    assert (
        'test, test.yaml, instances, foo: All entries in attribute `required` '
        'for `type` object must be defined in the`properties` attribute'
    ) in spec.errors


def test_value_type_unknown():
    spec = get_spec(
        """
        files:
        - name: test.yaml
          example_name: test.yaml.example
          sections:
          - name: instances
            options:
            - name: foo
              description: words
              value:
                type: custom
        """
    )
    spec.load()

    assert 'test, test.yaml, instances, foo: Unknown type `custom`' in spec.errors
