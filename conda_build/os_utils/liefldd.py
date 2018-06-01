import json
import lief
import os
import sys


def nm(filename):
    """ Return symbols from *filename* binary """
    binary  = lief.parse(filename) # Build an abstract binary
    symbols = binary.symbols

    if len(symbols) > 0:
        for symbol in symbols:
            print(dir(symbol))
            print(symbol)
    else:
        print("No symbols found")


def codefile_type(filename, skip_symlinks=True):
    if not os.path.exists(filename):
        return None
    binary = lief.parse(filename)
    # Future lief has this:
    # json_data = json.loads(lief.to_json_from_abstract(binary))
    json_data = json.loads(lief.to_json(binary))
    if json_data:
        # print(json.dumps(json_data, sort_keys = True, indent = 4))
        if 'format' in json_data and json_data['format'] == 'MACHO':
            return 'machofile'
        else:
            if 'header' in json_data and json_data['header']['file_type'] == 'DYNAMIC':
                return 'elffile'
            else:
                # Just to debug what else comes out.
                print(json_data['header']['file_type'])
                return 'elffile'+json_data['header']['file_type']
    return None

# lief cannot handle files it doesn't know about gracefully, so for now,
# use pyldd for this bit.
from .pyldd import codefile_type as codefile_type_pyldd
codefile_type = codefile_type_pyldd

def _trim_sysroot(sysroot):
    while sysroot.endswith('/') or sysroot.endswith('\\'):
        sysroot = sysroot[:-1]
    return sysroot

# TODO :: Consider memoizing instead of repeatedly scanning
# TODO :: libc.so/libSystem.dylib when inspect_linkages(recurse=True)
def _inspect_linkages_this(filename, sysroot='', arch='native'):
    '''

    :param filename:
    :param sysroot:
    :param arch:
    :return:
    '''

    if not os.path.exists(filename):
        return None, [], []
    sysroot = _trim_sysroot(sysroot)
    binary = lief.parse(filename)
    # Future lief has this:
    # json_data = json.loads(lief.to_json_from_abstract(binary))
    json_data = json.loads(lief.to_json(binary))
    if json_data:
        return filename, json_data['imported_libraries'], json_data['imported_libraries']
    return None, [], []


#    arch = _get_arch_if_native(arch)
#    with open(filename, 'rb') as f:
#        # TODO :: Problems here:
#        # TODO :: 1. macOS can modify RPATH for children in each .so
#        # TODO :: 2. Linux can identify the program interpreter which can change the default_paths
#        try:
#            cf = codefile(ReadCheckWrapper(f), arch)
#        except IncompleteRead:
#            # the file was incomplete, can occur if a package ships a test file
#            # which looks like an ELF file but is not.  Orange3 does this.
#            log.warning('problems inspecting linkages for {}'.format(filename))
#            return None, [], []
#        dirname = os.path.dirname(filename)
#        results = cf.get_resolved_shared_libraries(dirname, dirname, sysroot)
#        if not results:
#            return cf.uniqueness_key(), [], []
#        orig_names, resolved_names, _, in_sysroot = map(list, zip(*results))
#        return cf.uniqueness_key(), orig_names, resolved_names



# TODO :: Consider returning a tree structure or a dict when recurse is True?
def inspect_linkages_lief(filename, resolve_filenames=True, recurse=True, sysroot='', arch='native'):
    if not os.path.exists(filename):
        return []
    binary = lief.parse(filename)
    return binary.libraries


from .pyldd import inspect_linkages as inspect_linkages_pyldd
def inspect_linkages(filename, resolve_filenames=True, recurse=True, sysroot='', arch='native'):
    result_lief = inspect_linkages_lief(filename, resolve_filenames=resolve_filenames, recurse=recurse, sysroot=sysroot, arch=arch)
    result_pyldd = inspect_linkages_pyldd(filename, resolve_filenames=resolve_filenames, recurse=recurse, sysroot=sysroot, arch=arch)
    return result_pyldd


def get_runpaths(filename, arch='native'):
    if not os.path.exists(filename):
        return []
    binary = lief.parse(filename)
    # Future lief has this:
    # json_data = json.loads(lief.to_json_from_abstract(binary))
    json_data = json.loads(lief.to_json(binary))
    if json_data:
        if 'format' in json_data and json_data['format'] == 'MACHO':
            return []
    return [de.runpath for de in binary.dynamic_entries if de.tag == lief.ELF.DYNAMIC_TAGS.RUNPATH]


def get_imports(filename, arch='native'):
    if not os.path.exists(filename):
        return []
    binary = lief.parse(filename)
    json_data = json.loads(lief.to_json(binary))
    if 'imported_functions' in json_data:
        return json_data['imported_functions']
    return []


def get_exports(filename, arch='native'):
    if not os.path.exists(filename):
        return []
    if filename.endswith('.a') or filename.endswith('.lib'):
        # Crappy, sorry.
        import subprocess
        # syms = os.system('nm -g {}'.filename)
        # on macOS at least:
        # -PgUj is:
        # P: posix format
        # g: global (exported) only
        # U: not undefined
        # j is name only
        if sys.platform == 'darwin':
            flags = '-PgUj'
        else:
            flags = '-P'
        out, _ = subprocess.Popen(['nm', flags, filename], shell=False,
                         stdout=subprocess.PIPE).communicate()
        results = out.decode('utf-8').splitlines()
        exports = [r.split(' ')[0] for r in results if (' T ') in r]
        return exports
    else:
        binary = lief.parse(filename)
        json_data = json.loads(lief.to_json(binary))
        if 'exported_functions' in json_data:
            return json_data['exported_functions']
        return []


def get_symbols(filename, arch='native'):
    if not os.path.exists(filename):
        return []
    binary = lief.parse(filename)
    json_data = json.loads(lief.to_json(binary))
    if 'symbols' in json_data:
        return json_data['symbols']
    elif 'static_symbols' in json_data:
        return json_data['static_symbols']
    return []


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: " + sys.argv[0] + " <binary>")
        sys.exit(-1)

    nm(sys.argv[1])
