import os
import json

import pytest
import yaml

from conda_build import api, exceptions, variants
from conda_build.utils import package_has_file

thisdir = os.path.dirname(__file__)
recipe_dir = os.path.join(thisdir, 'test-recipes', 'variants')


def test_later_spec_priority(single_version, no_numpy_version):
    # override a single key
    combined_spec, extend_keys = variants.combine_specs([no_numpy_version, single_version])
    assert len(combined_spec) == 2
    assert combined_spec["python"] == ["2.7.*"]
    assert extend_keys == {'ignore_version', 'pin_run_as_build'}

    # keep keys that are not overwritten
    combined_spec, extend_keys = variants.combine_specs([single_version, no_numpy_version])
    assert len(combined_spec) == 2
    assert len(combined_spec["python"]) == 2


def test_get_package_variants_from_file(testing_workdir, testing_config, no_numpy_version):
    with open('variant_example.yaml', 'w') as f:
        yaml.dump(no_numpy_version, f, default_flow_style=False)
    testing_config.variant_config_files = [os.path.join(testing_workdir, 'variant_example.yaml')]
    testing_config.ignore_system_config = True
    metadata = api.render(os.path.join(thisdir, "variant_recipe"),
                            no_download_source=False, config=testing_config)
    # one for each Python version.  Numpy is not strictly pinned and should present only 1 dimension
    assert len(metadata) == 2
    assert sum('python >=2.7,<2.8' in req for (m, _, _) in metadata
               for req in m.meta['requirements']['run']) == 1
    assert sum('python >=3.5,<3.6' in req for (m, _, _) in metadata
               for req in m.meta['requirements']['run']) == 1


def test_use_selectors_in_variants(testing_workdir, testing_config):
    testing_config.variant_config_files = [os.path.join(recipe_dir,
                                                        'selector_conda_build_config.yaml')]
    variants.get_package_variants(testing_workdir, testing_config)


def test_get_package_variants_from_dictionary_of_lists(testing_config, no_numpy_version):
    testing_config.ignore_system_config = True
    metadata = api.render(os.path.join(thisdir, "variant_recipe"),
                          no_download_source=False, config=testing_config,
                          variants=no_numpy_version)
    # one for each Python version.  Numpy is not strictly pinned and should present only 1 dimension
    assert len(metadata) == 2, metadata
    assert sum('python >=2.7,<2.8' in req for (m, _, _) in metadata
               for req in m.meta['requirements']['run']) == 1
    assert sum('python >=3.5,<3.6' in req for (m, _, _) in metadata
               for req in m.meta['requirements']['run']) == 1


def test_combine_variants():
    v1 = {'python': '2.7.*', 'extend_keys': ['dict', 'list'], 'list': 'steve',
          'dict': {'some': 'value'}}
    v2 = {'python': '3.5.*', 'list': 'frank', 'dict': {'some': 'other', 'test': 'value'}}
    combined = variants.combine_variants(v1, v2)
    assert combined['python'] == '3.5.*'
    assert set(combined['list']) == {'steve', 'frank'}
    assert len(combined['dict']) == 2
    assert combined['dict']['some'] == 'other'


@pytest.mark.xfail(reason="Strange failure 7/19/2017.  Can't reproduce locally.  Test runs fine "
                   "with parallelism and everything.  Test fails reproducibly on CI, but logging "
                   "into appveyor after failed run, test passes.  =(")
def test_variant_with_ignore_numpy_version_reduces_matrix(numpy_version_ignored):
    # variants are defined in yaml file in this folder
    # there are two python versions and two numpy versions.  However, because numpy is not pinned,
    #    the numpy dimensions should get collapsed.
    recipe = os.path.join(recipe_dir, '03_numpy_matrix')
    metadata = api.render(recipe, variants=numpy_version_ignored, finalize=False)
    assert len(metadata) == 2, metadata


def test_variant_with_numpy_pinned_has_matrix():
    recipe = os.path.join(recipe_dir, '04_numpy_matrix_pinned')
    metadata = api.render(recipe, finalize=False)
    assert len(metadata) == 4


def test_pinning_in_build_requirements():
    recipe = os.path.join(recipe_dir, '05_compatible')
    metadata = api.render(recipe)[0][0]
    build_requirements = metadata.meta['requirements']['build']
    # make sure that everything in the build deps is exactly pinned
    assert all(len(req.split(' ')) == 3 for req in build_requirements)


def test_no_satisfiable_variants_raises_error():
    recipe = os.path.join(recipe_dir, '01_basic_templating')
    with pytest.raises(exceptions.DependencyNeedsBuildingError):
        api.render(recipe, permit_unsatisfiable_variants=False)

    # the packages are not installable anyway, so this should show a warning that recipe can't
    #   be finalized
    api.render(recipe, permit_unsatisfiable_variants=True)
    # out, err = capsys.readouterr()
    # print(out)
    # print(err)
    # print(caplog.text)
    # assert "Returning non-final recipe; one or more dependencies was unsatisfiable" in err


def test_zip_fields():
    """Zipping keys together allows people to tie different versions as sets of combinations."""
    v = {'python': ['2.7', '3.5'], 'vc': ['9', '14'], 'zip_keys': [('python', 'vc')]}
    ld = variants.dict_of_lists_to_list_of_dicts(v)
    assert len(ld) == 2
    assert ld[0]['python'] == '2.7'
    assert ld[0]['vc'] == '9'
    assert ld[1]['python'] == '3.5'
    assert ld[1]['vc'] == '14'

    # allow duplication of values, but lengths of lists must always match
    v = {'python': ['2.7', '2.7'], 'vc': ['9', '14'], 'zip_keys': [('python', 'vc')]}
    ld = variants.dict_of_lists_to_list_of_dicts(v)
    assert len(ld) == 2
    assert ld[0]['python'] == '2.7'
    assert ld[0]['vc'] == '9'
    assert ld[1]['python'] == '2.7'
    assert ld[1]['vc'] == '14'

    # mismatched lengths should raise an error
    v = {'python': ['2.7', '3.5', '3.4'], 'vc': ['9', '14'], 'zip_keys': [('python', 'vc')]}
    with pytest.raises(ValueError):
        ld = variants.dict_of_lists_to_list_of_dicts(v)

    # when one is completely missing, it's OK.  The zip_field for the set gets ignored.
    v = {'python': ['2.7', '3.5'], 'zip_keys': [('python', 'vc')]}
    ld = variants.dict_of_lists_to_list_of_dicts(v)
    assert len(ld) == 2
    assert 'vc' not in ld[0].keys()
    assert 'vc' not in ld[1].keys()


def test_cross_compilers():
    recipe = os.path.join(recipe_dir, '09_cross')
    outputs = api.get_output_file_paths(recipe, permit_unsatisfiable_variants=True)
    assert len(outputs) == 3


def test_variants_in_output_names():
    recipe = os.path.join(recipe_dir, '11_variant_output_names')
    outputs = api.get_output_file_paths(recipe)
    assert len(outputs) == 4


def test_variants_in_versions_with_setup_py_data(testing_workdir):
    recipe = os.path.join(recipe_dir, '12_variant_versions')
    outputs = api.get_output_file_paths(recipe)
    assert len(outputs) == 2
    assert any(os.path.basename(pkg).startswith('my_package-470.470') for pkg in outputs)
    assert any(os.path.basename(pkg).startswith('my_package-480.480') for pkg in outputs)


def test_git_variables_with_variants(testing_workdir, testing_config):
    recipe = os.path.join(recipe_dir, '13_git_vars')
    api.build(recipe, config=testing_config)


def test_variant_input_with_zip_keys_keeps_zip_keys_list():
    variants_ = [{'icu': '58', 'jpeg': '9', 'libdap4': '3.19', 'libkml': '1.3', 'libnetcdf': '4.4',
                 'libpng': '1.6', 'libtiff': '4.0', 'libxml2': '2.9', 'mkl': '2018',
                 'openblas': '0.2.19', 'proj4': '4', 'scipy': '0.17', 'sqlite': '3',
                 'zlib': '1.2', 'xz': '5',
                 'zip_keys': ['macos_min_version', 'macos_machine', 'MACOSX_DEPLOYMENT_TARGET',
                              'CONDA_BUILD_SYSROOT'],
                 'pin_run_as_build': {'python': {'min_pin': 'x.x', 'max_pin': 'x.x'}},
                 'macos_min_version': '10.9', 'macos_machine': 'x86_64-apple-darwin13.4.0',
                 'MACOSX_DEPLOYMENT_TARGET': '10.9', 'CONDA_BUILD_SYSROOT': '/opt/MacOSX10.9.sdk'}]
    variant_list = variants.dict_of_lists_to_list_of_dicts(variants_)
    assert len(variant_list) == 1


@pytest.mark.serial
def test_ensure_valid_spec_on_run_and_test(testing_workdir, testing_config, caplog):
    recipe = os.path.join(recipe_dir, '14_variant_in_run_and_test')
    api.render(recipe, config=testing_config)

    text = caplog.text
    assert "Adding .* to spec 'click  6'" in text
    assert "Adding .* to spec 'pytest  3.2'" in text
    assert "Adding .* to spec 'pytest-cov  2.3'" not in text
    assert "Adding .* to spec 'pytest-mock  1.6'" not in text


def test_serial_builds_have_independent_configs(testing_config):
    recipe = os.path.join(recipe_dir, '17_multiple_recipes_independent_config')
    recipes = [os.path.join(recipe, dirname) for dirname in ('a', 'b')]
    outputs = api.build(recipes, config=testing_config)
    index_json = json.loads(package_has_file(outputs[0], 'info/index.json'))
    assert 'bzip2 >=1,<1.0.7.0a0' in index_json['depends']
    index_json = json.loads(package_has_file(outputs[1], 'info/index.json'))
    assert 'bzip2 >=1.0.6,<2.0a0' in index_json['depends']


def test_get_used_loop_vars(testing_config):
    ms = api.render(os.path.join(recipe_dir, '19_used_variables'))
    # conda_build_config.yaml has 4 loop variables defined, but only 3 are used.
    #   python and zlib are both implicitly used (depend on name matching), while
    #   some_package is explicitly used as a jinja2 variable
    assert ms[0][0].get_used_loop_vars() == {'python', 'some_package', 'zlib'}


def test_reprovisioning_source(testing_config):
    ms = api.render(os.path.join(recipe_dir, '20_reprovision_source'))
