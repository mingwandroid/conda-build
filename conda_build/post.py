from __future__ import absolute_import, division, print_function

from collections.abc import Mapping
from collections import defaultdict, OrderedDict
from functools import partial
from fnmatch import fnmatch, translate, filter as fnmatch_filter
from os.path import (basename, commonprefix, dirname, exists, isabs, isdir, isfile,
                     islink, join, normpath, realpath, relpath)
try:
    from pathlib2 import Path, PurePath
except:
    from pathlib import Path, PurePath
import io
import locale
from multiprocessing import cpu_count
import json
import os
import re
import shutil
import stat
from subprocess import call, check_output, CalledProcessError
import sys
try:
    from os import readlink
except ImportError:
    readlink = False

from conda_build.os_utils import external
from conda_build.conda_interface import PY3
from conda_build.conda_interface import lchmod
from conda_build.conda_interface import linked_data
from conda_build.conda_interface import walk_prefix
from conda_build.conda_interface import TemporaryDirectory
from conda_build.conda_interface import md5_file

from conda_build import utils
from conda_build.os_utils.liefldd import (have_lief, get_exports_memoized,
                                          _get_path_dirs, get_rpaths_raw, set_rpath,
                                          lief_parse)
from conda_build.os_utils.pyldd import codefile_type
from conda_build.os_utils.ldd import get_package_obj_files
from conda_build.index import get_build_index
from conda_build.inspect_pkg import which_package
from conda_build.exceptions import (OverLinkingError, OverDependingError, RunPathError)

if sys.platform == 'darwin':
    from conda_build.os_utils import macho

if PY3:
    scandir = os.scandir
else:
    from scandir import scandir

filetypes_for_platform = {
    "win": ('DLLfile', 'EXEfile', 'pecoff'),
    "osx": ['machofile', 'macho'],
    "linux": ['elffile', 'elf', 'elf64'],
}


def fix_shebang(f, prefix, build_python, osx_is_app=False):
    path = join(prefix, f)
    if codefile_type(path):
        return
    elif islink(path):
        return
    elif not isfile(path):
        return

    if os.stat(path).st_size == 0:
        return

    bytes_ = False

    os.chmod(path, 0o775)
    with io.open(path, mode='r+', encoding=locale.getpreferredencoding()) as fi:
        try:
            data = fi.read(100)
            fi.seek(0)
        except UnicodeDecodeError:  # file is binary
            return

        SHEBANG_PAT = re.compile(r'^#!.+$', re.M)

        # regexp on the memory mapped file so we only read it into
        # memory if the regexp matches.
        try:
            mm = utils.mmap_mmap(fi.fileno(), 0, tagname=None, flags=utils.mmap_MAP_PRIVATE)
        except OSError:
            mm = fi.read()
        try:
            m = SHEBANG_PAT.match(mm)
        except TypeError:
            SHEBANG_PAT = re.compile(br'^#!.+$', re.M)
            bytes_ = True
            m = SHEBANG_PAT.match(mm)

        if m:
            python_pattern = (re.compile(br'\/python[w]?(?:$|\s|\Z)', re.M) if bytes_ else
                            re.compile(r'\/python[w]?(:$|\s|\Z)', re.M))
            if not re.search(python_pattern, m.group()):
                return
        else:
            return

        data = mm[:]

    py_exec = '#!' + ('/bin/bash ' + prefix + '/bin/pythonw'
               if sys.platform == 'darwin' and osx_is_app else
               prefix + '/bin/' + basename(build_python))
    if bytes_ and hasattr(py_exec, 'encode'):
        py_exec = py_exec.encode()
    new_data = SHEBANG_PAT.sub(py_exec, data, count=1)
    if new_data == data:
        return
    print("updating shebang:", f)
    with io.open(path, 'w', encoding=locale.getpreferredencoding()) as fo:
        try:
            fo.write(new_data)
        except TypeError:
            fo.write(new_data.decode())


def write_pth(egg_path, config):
    fn = basename(egg_path)
    py_ver = '.'.join(config.variant['python'].split('.')[:2])
    with open(join(utils.get_site_packages(config.host_prefix, py_ver),
                           '%s.pth' % (fn.split('-')[0])), 'w') as fo:
        fo.write('./%s\n' % fn)


def remove_easy_install_pth(files, prefix, config, preserve_egg_dir=False):
    """
    remove the need for easy-install.pth and finally remove easy-install.pth
    itself
    """
    absfiles = [join(prefix, f) for f in files]
    py_ver = '.'.join(config.variant['python'].split('.')[:2])
    sp_dir = utils.get_site_packages(prefix, py_ver)
    for egg_path in utils.glob(join(sp_dir, '*-py*.egg')):
        if isdir(egg_path):
            if preserve_egg_dir or not any(join(egg_path, i) in absfiles for i
                    in walk_prefix(egg_path, False, windows_forward_slashes=False)):
                write_pth(egg_path, config=config)
                continue

            print('found egg dir:', egg_path)
            try:
                shutil.move(join(egg_path, 'EGG-INFO'),
                          egg_path + '-info')
            except OSError:
                pass
            utils.rm_rf(join(egg_path, 'EGG-INFO'))
            for fn in os.listdir(egg_path):
                if fn == '__pycache__':
                    utils.rm_rf(join(egg_path, fn))
                else:
                    # this might be a name-space package
                    # so the package directory already exists
                    # from another installed dependency
                    if exists(join(sp_dir, fn)):
                        try:
                            utils.copy_into(join(egg_path, fn),
                                            join(sp_dir, fn), config.timeout,
                                            locking=config.locking)
                            utils.rm_rf(join(egg_path, fn))
                        except IOError as e:
                            fn = basename(str(e).split()[-1])
                            raise IOError("Tried to merge folder {egg_path} into {sp_dir}, but {fn}"
                                          " exists in both locations.  Please either add "
                                          "build/preserve_egg_dir: True to meta.yaml, or manually "
                                          "remove the file during your install process to avoid "
                                          "this conflict."
                                          .format(egg_path=egg_path, sp_dir=sp_dir, fn=fn))
                    else:
                        shutil.move(join(egg_path, fn), join(sp_dir, fn))

        elif isfile(egg_path):
            if egg_path not in absfiles:
                continue
            print('found egg:', egg_path)
            write_pth(egg_path, config=config)

    installer_files = [f for f in absfiles
                       if f.endswith(".dist-info{}INSTALLER".format(os.path.sep))]
    for file in installer_files:
        with open(file, 'w') as f:
            f.write('conda')

    utils.rm_rf(join(sp_dir, 'easy-install.pth'))


def rm_py_along_so(prefix):
    """remove .py (.pyc) files alongside .so or .pyd files"""

    files = list(scandir(prefix))
    for fn in files:
        if fn.is_file() and fn.name.endswith(('.so', '.pyd')):
            for ext in '.py', '.pyc', '.pyo':
                name, _ = os.path.splitext(fn.path)
                name = normpath(name + ext)
                if any(name == normpath(f) for f in files):
                    os.unlink(name + ext)


def rm_pyo(files, prefix):
    """pyo considered harmful: https://www.python.org/dev/peps/pep-0488/

    The build may have proceeded with:
        [install]
        optimize = 1
    .. in setup.cfg in which case we can end up with some stdlib __pycache__
    files ending in .opt-N.pyc on Python 3, as well as .pyo files for the
    package's own python. """
    re_pyo = re.compile(r'.*(?:\.pyo$|\.opt-[0-9]\.pyc)')
    for fn in files:
        if re_pyo.match(fn):
            os.unlink(join(prefix, fn))


def rm_pyc(files, prefix):
    re_pyc = re.compile(r'.*(?:\.pyc$)')
    for fn in files:
        if re_pyc.match(fn):
            os.unlink(join(prefix, fn))


def rm_share_info_dir(files, prefix):
    if 'share/info/dir' in files:
        fn = join(prefix, 'share', 'info', 'dir')
        if isfile(fn):
            os.unlink(fn)


def compile_missing_pyc(files, cwd, python_exe, skip_compile_pyc=()):
    if not isfile(python_exe):
        return
    compile_files = []
    skip_compile_pyc_n = [normpath(skip) for skip in skip_compile_pyc]
    skipped_files = set()
    for skip in skip_compile_pyc_n:
        skipped_files.update(set(fnmatch_filter(files, skip)))
    unskipped_files = set(files) - skipped_files
    for fn in unskipped_files:
        # omit files in Library/bin, Scripts, and the root prefix - they are not generally imported
        if sys.platform == 'win32':
            if any([fn.lower().startswith(start) for start in ['library/bin', 'library\\bin',
                                                               'scripts']]):
                continue
        else:
            if fn.startswith('bin'):
                continue
        cache_prefix = ("__pycache__" + os.sep) if PY3 else ""
        if (fn.endswith(".py") and
                dirname(fn) + cache_prefix + basename(fn) + 'c' not in files):
            compile_files.append(fn)

    if compile_files:
        if not isfile(python_exe):
            print('compiling .pyc files... failed as no python interpreter was found')
        else:
            print('compiling .pyc files...')
            # We avoid command lines longer than 8190
            if sys.platform == 'win32':
                limit = 8190
            else:
                limit = 32760
            limit -= len(compile_files) * 2
            lower_limit = len(max(compile_files, key=len)) + 1
            if limit < lower_limit:
                limit = lower_limit
            groups = [[]]
            args = [python_exe, '-Wi', '-m', 'py_compile']
            args_len = length = len(' '.join(args)) + 1
            for f in compile_files:
                length_this = len(f) + 1
                if length_this + length > limit:
                    groups.append([])
                    length = args_len
                else:
                    length += length_this
                groups[len(groups) - 1].append(f)
            for group in groups:
                call(args + group, cwd=cwd)


def check_dist_info_version(name, version, files):
    for f in files:
        if f.endswith('.dist-info' + os.sep + 'METADATA'):
            f_lower = basename(dirname(f).lower())
            if f_lower.startswith(name + '-'):
                f_lower, _, _ = f_lower.rpartition('.dist-info')
                _, distname, f_lower = f_lower.rpartition(name + '-')
                if distname == name and version != f_lower:
                    print("ERROR: Top level dist-info version incorrect (is {}, should be {})".format(f_lower, version))
                    sys.exit(1)
                else:
                    return


def post_process(name, version, files, prefix, config, preserve_egg_dir=False, noarch=False, skip_compile_pyc=()):
    rm_pyo(files, prefix)
    if noarch:
        rm_pyc(files, prefix)
    else:
        python_exe = (config.build_python if isfile(config.build_python) else
                      config.host_python)
        compile_missing_pyc(files, cwd=prefix, python_exe=python_exe,
                            skip_compile_pyc=skip_compile_pyc)
    remove_easy_install_pth(files, prefix, config, preserve_egg_dir=preserve_egg_dir)
    rm_py_along_so(prefix)
    rm_share_info_dir(files, prefix)
    check_dist_info_version(name, version, files)


def find_lib(link, prefix, files, path=None):
    if link.startswith(prefix):
        link = normpath(link[len(prefix) + 1:])
        if not any(link == normpath(w) for w in files):
            sys.exit("Error: Could not find %s" % link)
        return link
    if link.startswith('/'):  # but doesn't start with the build prefix
        return
    if link.startswith('@rpath/'):
        # Assume the rpath already points to lib, so there is no need to
        # change it.
        return
    if '/' not in link or link.startswith('@executable_path/'):
        link = basename(link)
        file_names = defaultdict(list)
        for f in files:
            file_names[basename(f)].append(f)
        if link not in file_names:
            sys.exit("Error: Could not find %s" % link)
        if len(file_names[link]) > 1:
            if path and basename(path) == link:
                # The link is for the file itself, just use it
                return path
            # Allow for the possibility of the same library appearing in
            # multiple places.
            md5s = set()
            for f in file_names[link]:
                md5s.add(md5_file(join(prefix, f)))
            if len(md5s) > 1:
                sys.exit("Error: Found multiple instances of %s: %s" % (link, file_names[link]))
            else:
                file_names[link].sort()
                print("Found multiple instances of %s (%s).  "
                    "Choosing the first one." % (link, file_names[link]))
        return file_names[link][0]
    print("Don't know how to find %s, skipping" % link)


def osx_ch_link(path, link_dict, host_prefix, build_prefix, files):
    link = link_dict['name']
    print("Fixing linking of %s in %s" % (link, path))
    if build_prefix != host_prefix and link.startswith(build_prefix):
        link = link.replace(build_prefix, host_prefix)
        print(".. seems to be linking to a compiler runtime, replacing build prefix with "
              "host prefix and")
        if not codefile_type(link):
            sys.exit("Error: Compiler runtime library in build prefix not found in host prefix %s"
                     % link)
        else:
            print(".. fixing linking of %s in %s instead" % (link, path))

    link_loc = find_lib(link, host_prefix, files, path)
    print("New link location is %s" % (link_loc))

    if not link_loc:
        return

    lib_to_link = relpath(dirname(link_loc), 'lib')
    # path_to_lib = utils.relative(path[len(prefix) + 1:])

    # e.g., if
    # path = '/build_prefix/lib/some/stuff/libstuff.dylib'
    # link_loc = 'lib/things/libthings.dylib'

    # then

    # lib_to_link = 'things'
    # path_to_lib = '../..'

    # @rpath always means 'lib', link will be at
    # @rpath/lib_to_link/basename(link), like @rpath/things/libthings.dylib.

    # For when we can't use @rpath, @loader_path means the path to the library
    # ('path'), so from path to link is
    # @loader_path/path_to_lib/lib_to_link/basename(link), like
    # @loader_path/../../things/libthings.dylib.

    ret = '@rpath/%s/%s' % (lib_to_link, basename(link))

    # XXX: IF the above fails for whatever reason, the below can be used
    # TODO: This might contain redundant ..'s if link and path are both in
    # some subdirectory of lib.
    # ret = '@loader_path/%s/%s/%s' % (path_to_lib, lib_to_link, basename(link))

    ret = ret.replace('/./', '/')

    return ret


def mk_relative_osx(path, host_prefix, build_prefix, files, rpaths=('lib',)):
    assert sys.platform == 'darwin'
    prefix = build_prefix if os.path.exists(build_prefix) else host_prefix
    names = macho.otool(path, prefix)
    s = macho.install_name_change(path, prefix,
                                  partial(osx_ch_link,
                                          host_prefix=host_prefix,
                                          build_prefix=build_prefix,
                                          files=files),
                                  dylibs=names)

    if names:
        # Add an rpath to every executable to increase the chances of it
        # being found.
        for rpath in rpaths:
            # Escape hatch for when you really don't want any rpaths added.
            if rpath == '':
                continue
            rpath_new = join('@loader_path',
                             relpath(join(host_prefix, rpath), dirname(path)),
                             '').replace('/./', '/')
            macho.add_rpath(path, rpath_new, build_prefix=prefix, verbose=True)
    if s:
        # Skip for stub files, which have to use binary_has_prefix_files to be
        # made relocatable.
        assert_relative_osx(path, host_prefix, build_prefix)


'''
# Both patchelf and LIEF have bugs in them. Neither can be used on all binaries we have seen.
# This code tries each and tries to keep count of which worked between the original binary and
# patchelf-patched, LIEF-patched versions.
#
# Please do not delete it until you are sure the bugs in both projects have been fixed.
#

from subprocess import STDOUT

def check_binary(binary, expected=None):
    from ctypes import cdll
    print("trying {}".format(binary))
    # import pdb; pdb.set_trace()
    try:
        txt = check_output([sys.executable, '-c', 'from ctypes import cdll; cdll.LoadLibrary("' + binary + '")'], timeout=2)
        # mydll = cdll.LoadLibrary(binary)
    except Exception as e:
        print(e)
        return None, None
    try:
        txt = check_output(binary, stderr=STDOUT, timeout=0.1)
    except Exception as e:
        print(e)
        txt = e.output
    if expected is not None:
        return txt == expected, txt
    return True, txt


worksd = {'original': 0,
          'LIEF': 0,
          'patchelf': 0}


def check_binary_patchers(elf, prefix, rpath):
    patchelf = external.find_executable('patchelf', prefix)
    tmpname_pe = elf+'.patchelf'
    tmpname_le = elf+'.lief'
    shutil.copy(elf, tmpname_pe)
    shutil.copy(elf, tmpname_le)
    import pdb; pdb.set_trace()
    works, original = check_binary(elf)
    if works:
        worksd['original'] += 1
        set_rpath(old_matching='*', new_rpath=rpath, file=tmpname_le)
        works, LIEF = check_binary(tmpname_le, original)
        call([patchelf, '--force-rpath', '--set-rpath', rpath, tmpname_pe])
        works, pelf = check_binary(tmpname_pe, original)
        if original == LIEF and works:
            worksd['LIEF'] += 1
        if original == pelf and works:
            worksd['patchelf'] += 1
    print('\n' + str(worksd) + '\n')
'''


def mk_relative_linux(f, prefix, rpaths=('lib',), method=None):
    'Respects the original values and converts abs to $ORIGIN-relative'

    elf = join(prefix, f)
    origin = dirname(elf)

    existing_pe = None
    patchelf = external.find_executable('patchelf', prefix)
    if not patchelf:
        print("ERROR :: You should install patchelf, will proceed with LIEF for {} (was {})".format(elf, method))
        method = 'LIEF'
    else:
        try:
            existing_pe = check_output([patchelf, '--print-rpath', elf]).decode('utf-8').splitlines()[0]
            existing_pe = existing_pe.split(':')
        except CalledProcessError:
            if method == 'patchelf':
                print("ERROR :: `patchelf --print-rpath` failed for {}, but patchelf was specified".format(
                    elf))
            elif method != 'LIEF':
                print("WARNING :: `patchelf --print-rpath` failed for {}, will proceed with LIEF (was {})".format(
                      elf, method))
            method = 'LIEF'
    existing = existing_pe
    if have_lief:
        existing2, _, _ = get_rpaths_raw(elf)
        # Flatten and resplit
        existing2 = ':'.join(existing2).split(':')
        if existing_pe and existing_pe != existing2:
            print('WARNING :: get_rpaths_raw()={} and patchelf={} disagree for {} :: '.format(
                      existing2, existing_pe, elf))
        # Use LIEF if method is LIEF to get the initial value?
        if method == 'LIEF':
            existing = existing2
    new = []
    for old in existing:
        if old.startswith('$ORIGIN'):
            new.append(old)
        elif old.startswith('/'):
            # Test if this absolute path is outside of prefix. That is fatal.
            rp = os.path.relpath(old, prefix)
            if rp.startswith('..' + os.sep):
                print('Warning: rpath {0} is outside prefix {1} (removing it)'.format(old, prefix))
            else:
                rp = '$ORIGIN/' + os.path.relpath(old, origin)
                if rp not in new:
                    new.append(rp)
    # Ensure that the asked-for paths are also in new.
    for rpath in rpaths:
        if rpath != '':
            if not rpath.startswith('/'):
                # IMHO utils.relative shouldn't exist, but I am too paranoid to remove
                # it, so instead, make sure that what I think it should be replaced by
                # gives the same result and assert if not. Yeah, I am a chicken.
                rel_ours = normpath(utils.relative(f, rpath))
                rel_stdlib = normpath(relpath(rpath, dirname(f)))
                if not rel_ours == rel_stdlib:
                    raise ValueError('utils.relative {0} and relpath {1} disagree for {2}, {3}'.format(
                        rel_ours, rel_stdlib, f, rpath))
                rpath = '$ORIGIN/' + rel_stdlib
            if rpath not in new:
                new.append(rpath)
    rpath = ':'.join(new)

    # check_binary_patchers(elf, prefix, rpath)
    if not method or not patchelf or method.upper() == 'LIEF':
        set_rpath(old_matching='*', new_rpath=rpath, file=elf)
    else:
        call([patchelf, '--force-rpath', '--set-rpath', rpath, elf])


def assert_relative_osx(path, host_prefix, build_prefix):
    tools_prefix = build_prefix if os.path.exists(build_prefix) else host_prefix
    for name in macho.get_dylibs(path, tools_prefix):
        for prefix in (host_prefix, build_prefix):
            if prefix and name.startswith(prefix):
                raise RuntimeError("library at %s appears to have an absolute path embedded" % path)


def determine_package_nature(pkg, prefix, subdir, bldpkgs_dir, output_folder, channel_urls):
    dsos = []
    run_exports = None
    lib_prefix = pkg.name.startswith('lib')
    codefiles = get_package_obj_files(pkg, prefix)
    # get_package_obj_files already filters by extension and I'm not sure we need two.
    dsos = [f for f in codefiles for ext in ('.dylib', '.so', '.dll', '.pyd') if ext in f]
    # we don't care about the actual run_exports value, just whether or not run_exports are present.
    # We can use channeldata and it'll be a more reliable source (no disk race condition nonsense)
    _, _, channeldata = get_build_index(subdir=subdir,
                                        bldpkgs_dir=bldpkgs_dir,
                                        output_folder=output_folder,
                                        channel_urls=channel_urls,
                                        debug=False,
                                        verbose=False,
                                        clear_cache=False)
    channel_used = pkg.channel
    channeldata = channeldata.get(channel_used)

    if channeldata and pkg.name in channeldata['packages']:
        run_exports = channeldata['packages'][pkg.name].get('run_exports', {})
    return (dsos, run_exports, lib_prefix)


def library_nature(pkg, prefix, subdir, bldpkgs_dirs, output_folder, channel_urls):
    '''
    Result :: "non-library", "plugin library", "dso library", "run-exports library"
    .. in that order, i.e. if have both dsos and run_exports, it's a run_exports_library.
    '''
    dsos, run_exports, _ = determine_package_nature(pkg, prefix, subdir, bldpkgs_dirs, output_folder, channel_urls)
    if run_exports:
        return "run-exports library"
    elif len(dsos):
        # If all DSOs are under site-packages or R/lib/
        dsos_without_plugins = [dso for dso in dsos
                                if not any(part for part in ('lib/R/library', 'site-packages')
                                           if part in dso)]
        if len(dsos_without_plugins):
            return "dso library"
        else:
            return "plugin library"
    return "non-library"


def dists_from_names(names, prefix):
    results = []
    pkgs = linked_data(prefix)
    for name in names:
        for pkg in pkgs:
            if pkg.quad[0] == name:
                results.append(pkg)
    return results


class FakeDist:
    def __init__(self, name, version, build_number, build_str):
        self.name = name
        self.quad = [name]
        self.version = version
        self.build_number = build_number
        self.build_string = build_str


DEFAULT_MAC_WHITELIST = ['/opt/X11/',
                         '/usr/lib/libSystem.B.dylib',
                         '/usr/lib/libcrypto.0.9.8.dylib',
                         '/usr/lib/libobjc.A.dylib',
                         '/System/Library/Frameworks/Accelerate.framework/*',
                         '/System/Library/Frameworks/AGL.framework/*',
                         '/System/Library/Frameworks/AppKit.framework/*',
                         '/System/Library/Frameworks/ApplicationServices.framework/*',
                         '/System/Library/Frameworks/AudioToolbox.framework/*',
                         '/System/Library/Frameworks/AudioUnit.framework/*',
                         '/System/Library/Frameworks/AVFoundation.framework/*',
                         '/System/Library/Frameworks/CFNetwork.framework/*',
                         '/System/Library/Frameworks/Carbon.framework/*',
                         '/System/Library/Frameworks/Cocoa.framework/*',
                         '/System/Library/Frameworks/CoreAudio.framework/*',
                         '/System/Library/Frameworks/CoreFoundation.framework/*',
                         '/System/Library/Frameworks/CoreGraphics.framework/*',
                         '/System/Library/Frameworks/CoreMedia.framework/*',
                         '/System/Library/Frameworks/CoreBluetooth.framework/*',
                         '/System/Library/Frameworks/CoreMIDI.framework/*',
                         '/System/Library/Frameworks/CoreMedia.framework/*',
                         '/System/Library/Frameworks/CoreServices.framework/*',
                         '/System/Library/Frameworks/CoreText.framework/*',
                         '/System/Library/Frameworks/CoreVideo.framework/*',
                         '/System/Library/Frameworks/CoreWLAN.framework/*',
                         '/System/Library/Frameworks/DiskArbitration.framework/*',
                         '/System/Library/Frameworks/Foundation.framework/*',
                         '/System/Library/Frameworks/GameController.framework/*',
                         '/System/Library/Frameworks/GLKit.framework/*',
                         '/System/Library/Frameworks/ImageIO.framework/*',
                         '/System/Library/Frameworks/IOBluetooth.framework/*',
                         '/System/Library/Frameworks/IOKit.framework/*',
                         '/System/Library/Frameworks/IOSurface.framework/*',
                         '/System/Library/Frameworks/OpenAL.framework/*',
                         '/System/Library/Frameworks/OpenGL.framework/*',
                         '/System/Library/Frameworks/Quartz.framework/*',
                         '/System/Library/Frameworks/QuartzCore.framework/*',
                         '/System/Library/Frameworks/Security.framework/*',
                         '/System/Library/Frameworks/StoreKit.framework/*',
                         '/System/Library/Frameworks/SystemConfiguration.framework/*',
                         '/System/Library/Frameworks/WebKit.framework/*']

# These are relative to os.environ['windir'] (generally C:/Windows).
DEFAULT_WIN_WHITELIST = ['/System32/ADVAPI32.dll',
                         '/System32/bcrypt.dll',
                         '/System32/COMCTL32.dll',
                         '/System32/COMDLG32.dll',
                         '/System32/CRYPT32.dll',
                         '/System32/dbghelp.dll',
                         '/System32/GDI32.dll',
                         '/System32/IMM32.dll',
                         '/System32/KERNEL32.dll',
                         '/System32/NETAPI32.dll',
                         '/System32/ole32.dll',
                         '/System32/OLEAUT32.dll',
                         '/System32/PSAPI.DLL',
                         '/System32/RPCRT4.dll',
                         '/System32/SHELL32.dll',
                         '/System32/USER32.dll',
                         '/System32/USERENV.dll',
                         '/System32/WINHTTP.dll',
                         '/System32/WS2_32.dll',
                         '/System32/ntdll.dll',
                         '/System32/msvcrt.dll',
                         '/System32/**/api-ms-win*.dll']

def _get_rpaths(lib_info, selfdir):
    rpaths = [f.replace('$SELFDIR', selfdir) for f in \
              (lib_info['runpaths'] if len(lib_info['runpaths']) else lib_info['rpaths'])]
    return rpaths


def _resolve_needed_dsos(ld_library_path, sysroots_files, libs_info, run_prefix,
                         sysroot_substitution, build_prefix, build_prefix_substitution):
    '''
    :param ld_library_path: An ordered list of directories to search for. This is modified and stored
                           with each DSO we process according to its RPATH entries. Recursion is not
                           needed for any of this.
    :param sysroots_files: A dict of sysroots and their files.
    :param libs_info: The raw input information pertaining to each DSO as returned by LIEF (or pyldd).
    :param run_prefix:
    :param sysroot_substitution:
    :param build_prefix:
    :param build_prefix_substitution:
    :return:
    '''

    res = {}

    for f, lib_info in libs_info.items():

        # We must clear this out before each DSO is checked as the same SONAME could
        # be reached from different search paths.
        res = {}

        if 'dylib' in f:
            print('debug')
        if 'filetype' not in lib_info or 'original' not in lib_info['libraries']:
            print("Skipping {}".format(f))
            continue
        build_prefix = build_prefix.replace(os.sep, '/')
        run_prefix = run_prefix.replace(os.sep, '/')

        # runpaths take precedence (but we have other checks for those, still if they are disabled
        # for some reason we should respect that). runpaths are not transitive though and that is
        # not handled here.
        selfdir = os.path.dirname(lib_info['fullpath'])
        if 'bar_exe' in f:
            print("debug")
        rpaths = _get_rpaths(lib_info, selfdir)
        res[lib_info['key']] = {'ld_library_path': rpaths + ld_library_path,
                                # Resolved is a list of the same record type!
                                'resolved': []}
        # This is only a single level of resolution.
        libraries_original = lib_info['libraries']['original']
        for lib in libraries_original:
            parent_rpaths = res[lib_info['key']]['ld_library_path']
            for path in parent_rpaths:
                fullpath = join(path, lib)
                if os.path.exists(fullpath):
                    rp = os.path.relpath(fullpath, run_prefix)
                    lib_info2 = libs_info[rp]
                    selfdir2 = os.path.dirname(lib_info2['fullpath'])
                    rpaths = _get_rpaths(lib_info2, selfdir2)
                    res[lib_info2['key']] = {'ld_library_path': rpaths + parent_rpaths,
                                             # Resolved is a list of the same record type!
                                             'resolved': []}
                    res[f]['resolved'].append(fullpath)
                    break
            else:
                print("ERROR :: Didn't find {} for {}".format(lib, f))
        if f in res and 'resolved' in res[f]:
            lib_info['libraries']['resolved'] = res[f]['resolved']

        # Only the pyldd version of lief_parse (yeah, I know, the name, right?) sets 'libraries/resolved'.
        # .. may as well check it gets the same result as doing it here (chances are high it does not =>
        # also note, we have not called our liefldd resolver at all yet. It is in
        # if 'resolved' in lib_info['libraries']:
        #     assert lib_info['libraries']['resolved'] == needed, "pyldd's resolver disagrees"
        # if lib_info['libraries']['original'] != needed:
        #     print("Yes, _resolve_needed_dsos did change\n{} .. to ..\n{}".format(lib_info['libraries']['original'], needed))
        # lib_info['libraries']['resolved'] = needed


def _map_file_to_package(files, run_prefix, build_prefix, all_needed_dsos, pkg_vendored_dist, ignore_list_syms, sysroot_substitution, enable_static):
    # Form a mapping of file => package
    prefix_owners = {}
    contains_dsos = {}
    contains_static_libs = {}
    # Used for both dsos and static_libs
    all_lib_exports = {}
    if all_needed_dsos:
        for prefix in (run_prefix, build_prefix):
            for subdir2, _, filez in os.walk(prefix):
                for file in filez:
                    fp = join(subdir2, file)
                    dynamic_lib = any(fnmatch(fp, ext) for ext in ('*.so.*', '*.dylib.*', '*.dll')) and \
                                codefile_type(fp, skip_symlinks=False) is not None
                    static_lib = any(fnmatch(fp, ext) for ext in ('*.a', '*.lib'))
                    static_lib = False
                    # Looking at all the files is very slow.
                    if not dynamic_lib and not static_lib:
                        continue
                    rp = normpath(os.path.relpath(fp, prefix))
                    if dynamic_lib and not any(rp == normpath(w) for w in all_needed_dsos):
                        continue
                    if any(rp == normpath(w) for w in all_lib_exports):
                        continue
                    owners = prefix_owners[rp] if rp in prefix_owners else []
                    # Self-vendoring, not such a big deal but may as well report it?
                    if not len(owners):
                        if any(rp == normpath(w) for w in files):
                            owners.append(pkg_vendored_dist)
                    new_pkgs = list(which_package(rp, prefix))
                    # Cannot filter here as this means the DSO (eg libomp.dylib) will not be found in any package
                    # [owners.append(new_pkg) for new_pkg in new_pkgs if new_pkg not in owners
                    #  and not any([fnmatch(new_pkg.name, i) for i in ignore_for_statics])]
                    for new_pkg in new_pkgs:
                        if new_pkg not in owners:
                            owners.append(new_pkg)
                    prefix_owners[rp] = owners
                    if len(prefix_owners[rp]):
                        exports = set(e for e in get_exports_memoized(fp, enable_static=enable_static) if not
                                    any(fnmatch(e, pattern) for pattern in ignore_list_syms))
                        all_lib_exports[rp] = exports
                        # Check codefile_type to filter out linker scripts.
                        if dynamic_lib:
                            contains_dsos[prefix_owners[rp][0]] = True
                        elif static_lib:
                            if sysroot_substitution in fp:
                                if (prefix_owners[rp][0].name.startswith('gcc_impl_linux') or
                                prefix_owners[rp][0].name == 'llvm'):
                                    continue
                                print("sysroot in {}, owner is {}".format(fp, prefix_owners[rp][0]))
                            contains_static_libs[prefix_owners[rp][0]] = True
    return prefix_owners, contains_dsos, contains_static_libs


def _get_fake_pkg_dist(pkg_name, pkg_version, build_str, build_number):
    pkg_vendoring_name = pkg_name
    pkg_vendoring_version = str(pkg_version)
    pkg_vendoring_build_str = build_str
    pkg_vendoring_build_number = build_number
    pkg_vendoring_key = '-'.join([pkg_vendoring_name,
                                  pkg_vendoring_version,
                                  pkg_vendoring_build_str])

    return FakeDist(pkg_vendoring_name,
                    pkg_vendoring_version,
                    pkg_vendoring_build_number,
                    pkg_vendoring_build_str), pkg_vendoring_key


def _print_msg(errors, text, verbose):
    if text.startswith("  ERROR"):
        errors.append(text)
    if verbose:
        print(text)


def _lookup_in_system_whitelists(errors, whitelist, needed_dso, sysroots_files, msg_prelude, info_prelude,
                                 sysroot_prefix, sysroot_substitution, verbose):
    # A system or ignored dependency. We should be able to find it in one of the CDT or
    # compiler packages on linux or in a sysroot folder on other OSes. These usually
    # start with '$RPATH/' which indicates pyldd did not find them, so remove that now.
    if needed_dso.startswith(sysroot_substitution):
        replacements = [sysroot_substitution] + [sysroot for sysroot, _ in sysroots_files.items()]
    else:
        replacements = [needed_dso]
    in_whitelist = False
    # It takes a very long time to glob in C:/Windows so cache it.
    for replacement in replacements:
        needed_dso_w = needed_dso.replace(sysroot_substitution, replacement)
        in_whitelist = any([fnmatch(needed_dso_w, w) for w in whitelist])
        if in_whitelist:
            n_dso_p = "Needed DSO {}".format(needed_dso_w)
            _print_msg(errors, '{}: {} found in the whitelist'.
                       format(info_prelude, n_dso_p), verbose=verbose)
            break
    if not in_whitelist and len(sysroots_files):
        # Check if we have a CDT package.
        dso_fname = basename(needed_dso)
        sysroot_files = []
        for sysroot, files in sysroots_files.items():
            sysroot_os = sysroot.replace('/', os.sep)
            wild = join('**', dso_fname)
            if needed_dso.startswith(sysroot_substitution):
                # Do we want to do this replace?
                sysroot_files.append(needed_dso.replace(sysroot_substitution, sysroot_os))
            else:
                found = [file for file in files if fnmatch(file, wild)]
                sysroot_files.extend(found)
        if len(sysroot_files):
            # Removing sysroot_prefix is only *really* for Linux, though we could
            # use CONDA_BUILD_SYSROOT for macOS. We should figure out what to do about
            # /opt/X11 too.
            # Find the longest suffix match.
            rev_needed_dso = needed_dso[::-1]
            match_lens = [len(commonprefix([s[::-1], rev_needed_dso]))
                            for s in sysroot_files]
            idx = max(range(len(match_lens)), key=match_lens.__getitem__)
            in_prefix_dso = normpath(sysroot_files[idx].replace(
                sysroot_prefix + os.sep, ''))
            n_dso_p = "Needed DSO {}".format(in_prefix_dso)
            pkgs = list(which_package(in_prefix_dso, sysroot_prefix))
            if len(pkgs):
                _print_msg(errors, '{}: {} found in CDT/compiler package {}'.
                                    format(info_prelude, n_dso_p, pkgs[0]), verbose=verbose)
            else:
                _print_msg(errors, '{}: {} not found in any CDT/compiler package,'
                                    ' nor the whitelist?!'.
                                format(msg_prelude, n_dso_p), verbose=verbose)
        else:
            _print_msg(errors, "{}: {} not found in sysroot, is this binary repackaging?"
                                " .. do you need to use install_name_tool/patchelf?".
                                format(msg_prelude, needed_dso), verbose=verbose)
    elif not in_whitelist:
        _print_msg(errors, "{}: did not find - or even know where to look for: {}".
                            format(msg_prelude, needed_dso), verbose=verbose)


def _lookup_in_prefix_packages(errors, needed_dso, files, run_prefix, whitelist, info_prelude, msg_prelude,
                               warn_prelude, verbose, requirements_run, lib_packages, lib_packages_used):
    in_prefix_dso = normpath(needed_dso)
    n_dso_p = "Needed DSO {}".format(in_prefix_dso)
    and_also = " (and also in this package)" if in_prefix_dso in files else ""
    pkgs = list(which_package(in_prefix_dso, run_prefix))
    in_pkgs_in_run_reqs = [pkg for pkg in pkgs if pkg.quad[0] in requirements_run]
    # TODO :: metadata build/inherit_child_run_exports (for vc, mro-base-impl).
    for pkg in in_pkgs_in_run_reqs:
        if pkg in lib_packages:
            lib_packages_used.add(pkg)
    in_whitelist = any([fnmatch(in_prefix_dso, w) for w in whitelist])
    if len(in_pkgs_in_run_reqs) == 1:
        _print_msg(errors, '{}: {} found in {}{}'.format(info_prelude,
                                                        n_dso_p,
                                                        in_pkgs_in_run_reqs[0],
                                                        and_also), verbose=verbose)
    elif in_whitelist:
        _print_msg(errors, '{}: {} found in the whitelist'.
                    format(info_prelude, n_dso_p), verbose=verbose)
    elif len(in_pkgs_in_run_reqs) == 0 and len(pkgs) > 0:
        _print_msg(errors, '{}: {} found in {}{}'.format(msg_prelude,
                                                        n_dso_p,
                                                        [p.quad[0] for p in pkgs],
                                                        and_also), verbose=verbose)
        _print_msg(errors, '{}: .. but {} not in reqs/run, (i.e. it is overlinking)'
                            ' (likely) or a missing dependency (less likely)'.
                            format(msg_prelude, [p.quad[0] for p in pkgs]), verbose=verbose)
    elif len(in_pkgs_in_run_reqs) > 1:
        _print_msg(errors, '{}: {} found in multiple packages in run/reqs: {}{}'
                            .format(warn_prelude,
                                    in_prefix_dso,
                                    in_pkgs_in_run_reqs,
                                    and_also), verbose=verbose)
    else:
        if not any(in_prefix_dso == normpath(w) for w in files):
            _print_msg(errors, '{}: {} not found in any packages'.format(msg_prelude,
                                                                        in_prefix_dso), verbose=verbose)
        elif verbose:
            _print_msg(errors, '{}: {} found in this package'.format(info_prelude,
                                                                     in_prefix_dso), verbose=verbose)


def _show_linking_messages(files, errors, file_info, build_prefix, run_prefix, pkg_name,
                           error_overlinking, runpath_whitelist, verbose, requirements_run, lib_packages,
                           lib_packages_used, whitelist, sysroots, sysroot_prefix, sysroot_substitution, subdir):
    for f in files:
        path = join(run_prefix, f)
        filetype = codefile_type(path)
        if not filetype or filetype not in filetypes_for_platform[subdir.split('-')[0]]:
            continue
        warn_prelude = "WARNING ({},{})".format(pkg_name, f)
        err_prelude = "  ERROR ({},{})".format(pkg_name, f)
        info_prelude = "   INFO ({},{})".format(pkg_name, f)
        msg_prelude = err_prelude if error_overlinking else warn_prelude
        runpaths = file_info[f]['runpaths'] if 'runpaths' in file_info[f] else None  # TODO :: Check why these aren't getting set.
        if runpaths and not (runpath_whitelist or
                             any(fnmatch(f, w) for w in runpath_whitelist)):
            _print_msg(errors, '{}: runpaths {} found in {}'.format(msg_prelude,
                                                                    runpaths,
                                                                    path), verbose=verbose)
        needed = file_info[f]['libraries']['resolved'] if 'resolved' in file_info[f]['libraries'] else []  # TODO :: Check why these aren't getting set.
        for needed_dso in needed:
            needed_dso = needed_dso.replace('/', os.sep)
            if not needed_dso.startswith(os.sep) and not needed_dso.startswith('$'):
                _lookup_in_prefix_packages(errors, needed_dso, files, run_prefix, whitelist, info_prelude, msg_prelude,
                               warn_prelude, verbose, requirements_run, lib_packages, lib_packages_used)
            elif needed_dso.startswith('$PATH'):
                _print_msg(errors, "{}: {} found in build prefix; should never happen".format(
                           err_prelude, needed_dso), verbose=verbose)
            else:
                _lookup_in_system_whitelists(errors, whitelist, needed_dso, sysroots, msg_prelude,
                                             info_prelude, sysroot_prefix, sysroot_substitution, verbose)


class FrozenDict(Mapping):
    """Don't forget the docstrings!!"""

    def __init__(self, *args, **kwargs):
        self._d = dict(*args, **kwargs)
        self._hash = None

    def __iter__(self):
        return iter(self._d)

    def __len__(self):
        return len(self._d)

    def __getitem__(self, key):
        return self._d[key]

    def __hash__(self):
        # It would have been simpler and maybe more obvious to
        # use hash(tuple(sorted(self._d.iteritems()))) from this discussion
        # so far, but this solution is O(n). I don't know what kind of
        # n we are going to run into, but sometimes it's hard to resist the
        # urge to optimize when it will gain improved algorithmic performance.
        if self._hash is None:
            self._hash = 0
            for k, v in self.items():
                if isinstance(v, set):
                    v = frozenset(v)
                self._hash ^= hash(k)
                self._hash ^= hash(v)
        return self._hash


def check_overlinking_impl(pkg_name, pkg_version, build_str, build_number, subdir,
                           ignore_run_exports,
                           requirements_run, requirements_build, requirements_host,
                           run_prefix, build_prefix,
                           missing_dso_whitelist, runpath_whitelist,
                           error_overlinking, error_overdepending, verbose,\
                           exception_on_error, files, bldpkgs_dirs, output_folder, channel_urls,
                           sysroot):
    errors = []

    sysroot_sub = '$SYSROOT'
    buildprefix_sub = '$BUILDPREFIX'
    runprefix_sub = '$RUNPREFIX'
    exedirname_sub = '$EXEDIRNAME'

    path_replacements = {"runprefix": {run_prefix: runprefix_sub}}

    if build_prefix != run_prefix:
        path_replacements["buildprefix"] = {build_prefix: buildprefix_sub}

    # Used to detect overlinking (finally)
    requirements_run = [req.split(' ')[0] for req in requirements_run]
    packages = dists_from_names(requirements_run, run_prefix)
    ignore_list = utils.ensure_list(ignore_run_exports)
    if subdir.startswith('linux'):
        ignore_list.append('libgcc-ng')
    package_nature = {package: library_nature(package, run_prefix, subdir, bldpkgs_dirs, output_folder, channel_urls)
                      for package in packages}
    lib_packages = set([package for package in packages
                        if package.quad[0] not in ignore_list and
                        package_nature[package] != 'non-library'])
    # The last package of requirements_run is this package itself, add it as being used
    # in case it qualifies as a library package.
    if len(packages) and packages[-1] in lib_packages:
        lib_packages_used = set((packages[-1],))
    else:
        lib_packages_used = set()

    pkg_vendored_dist, pkg_vendoring_key = _get_fake_pkg_dist(pkg_name, pkg_version, build_str, build_number)

    # ignore_list_syms = ['main', '_main', '*get_pc_thunk*', '___clang_call_terminate', '_timeout']
    # ignore_for_statics = ['gcc_impl_linux*', 'compiler-rt*', 'llvm-openmp*', 'gfortran_osx*']
    # sysroots and whitelists are similar, but the subtle distinctions are important.
    sysroot_prefix = build_prefix
    if sysroot:
        sysroots = [sysroot]
    else:
        sysroots = [sysroot + os.sep for sysroot in utils.glob(join(sysroot_prefix, '**', 'sysroot'))]
    whitelist = []
    vendoring_record = dict()
    # When build_is_host is True we perform file existence checks for files in the sysroot (e.g. C:\Windows)
    # When build_is_host is False we must skip things that match the whitelist from the prefix_owners (we could
    #   create some packages for the Windows System DLLs as an alternative?)
    build_is_host = False
    if subdir == 'osx-64':
        whitelist = DEFAULT_MAC_WHITELIST
        build_is_host = True if sys.platform == 'darwin' else False
    elif subdir.startswith('win'):
        whitelist = DEFAULT_WIN_WHITELIST
        # What about win-32 vs win-64 here?
        build_is_host = True if sys.platform == 'win-32' else False
    # Defaults. Eventually this should be passed in on all systems.
    if not len(sysroots):
        if subdir == 'osx-64':
            # This is a bit confused! A sysroot shouldn't contain /usr/lib (it's the bit before that)
            # what we are really specifying here are subtrees of sysroots to search in and it may be
            # better to store each element of this as a tuple with a string and a nested tuple, e.g.
            # [('/', ('/usr/lib', '/opt/X11', '/System/Library/Frameworks'))]
            # Here we mean that we have a sysroot at '/' (could be a tokenized value like '$SYSROOT'?)
            # .. and in that sysroot there are 3 suddirs in which we may search for DSOs.
            sysroots = ['/opt/MacOSX10.9.sdk']
        elif subdir.startswith('win'):
            sysroots = [os.environ['windir'].replace('\\', '/')] if sys.platform == 'win32' else ['C:/Windows']

    sysroots_files = dict()
    for sysroot in sysroots:
        from conda_build.utils import prefix_files
        sysroots_files[sysroot] = prefix_files(sysroot)
    sysroots_files = OrderedDict(sorted(sysroots_files.items(), key=lambda x: -len(x[1])))
    for index, sysroot in enumerate(sysroots_files):
        path_replacements['sysroot' + str(index)] = {sysroot: sysroot_sub[:0] + str(index)}
        if 'Windows' in sysroot and len(sysroots_files):
            path_replacements['windowsroot'] = {sysroot: sysroot_sub[:0] + str(index)}

    # file_info collects any and all information about the files present.
    # Process only the packaged files.
    file_info = dict()
    program_files = [f for f in files if (codefile_type(join(run_prefix, f)) or
                     codefile_type(join(run_prefix, f)) in filetypes_for_platform[subdir.split('-')[0]]) or
                     f.endswith(('.a', '.lib'))]

    # We care only for created program binaries (exes and DSOs) and static libs
    program_files = [p for p in program_files if not p.endswith('.debug')]
    from concurrent.futures import ThreadPoolExecutor

    def lief_parse_this(filename, path_replacements):
        path_replacements_this = path_replacements.copy()
        path_replacements_this['exedirname'] = {join(run_prefix, dirname(f)).replace('\\', '/'): exedirname_sub}
        return lief_parse(filename, path_replacements_this)

    parallel = True
    serial = False

    if serial:
        file_info_serial = dict()
        for f in program_files:
            file_info_serial[f] = lief_parse_this(join(run_prefix, f), path_replacements)

    if parallel:
        file_info_parallel = dict()
        results = {}
        with ThreadPoolExecutor(min(cpu_count(), max(1, len(program_files)))) as executor:
            for f in program_files:
                results[f] = executor.submit(lief_parse_this, join(run_prefix, f), path_replacements)

        for f in program_files:
            file_info_parallel[f] = results[f].result()

    if serial and parallel:
        assert file_info_serial == file_info_parallel

    if parallel:
        file_info = file_info_parallel
    else:
        file_info = file_info_serial

    if verbose:
        print('\n'.join(f + " : \n" + json.dumps(v, indent=4) for f, v in file_info.items()))

    # Resolving DSO concerns:
    # 1. Different exes could provide different RPATHs from each other which could affect where the
    #    needed DSOs (which are only filenames at this point) are found. This can lead to the same
    #    dso being found in multiple locations .... so .... we will have file_info for all versions
    #    of the same DSO. Should they happen to be the same binary our caching will *not* collapse
    #    them to a single file_info, instead they are deep copied and the copy augmented with the
    #    'fullpath' to each copy of that file.
    # 2. So we need to only resolve DSOs used by executables, we will not resolve DSO references in
    #    other DSOs into any kind of a record that we report or generate errors based upon.

    # The end, OS specific bit of this should come from the sysroot files .py if they exist,
    # or else we should allow explicit specification of them in conda_build_config.yaml
    if subdir == 'linux-64':
        def_libdirs = ['lib64', 'lib']
    else:
        def_libdirs = ['lib']
    ld_library_path = list(_get_path_dirs(run_prefix, subdir)) + [
        '{sysroot}usr/{lib}'.format(sysroot=sysroots[0],
                                    lib=def_libdir) for def_libdir in def_libdirs] \
                          if subdir.startswith('linux') else [
        '{SystemRoot}/system32',
        '{SystemRoot}',
        '{SystemRoot}/System32/Wbem',
        '{SystemRoot}/System32/WindowsPowerShell/v1.0']
    _resolve_needed_dsos(ld_library_path,
                         sysroots_files,
                         file_info,
                         run_prefix,
                         sysroot_sub,
                         build_prefix,
                         buildprefix_sub)
    for prefix in (run_prefix, build_prefix):
        for subdir2, _, filez in os.walk(prefix):
            for file in filez:
                if file.endswith('libterm-bd8f21e3bdd6cbdc.so'):
                    print("Why does this not make it?")
                fullpath = join(subdir2, file)
                rp = relpath(fullpath, prefix)
                if rp in file_info:
                    if prefix is run_prefix:
                        file_info[rp]['package'] = pkg_vendored_dist
                        assert file_info[rp]['fullpath'] == fullpath
                elif rp in files:
                    file_info[rp] = {'package': pkg_vendored_dist,
                                     'fullpath': fullpath}
                else:
                    file_info[rp] = {'package': which_package(rp, prefix),
                                     'fullpath': fullpath}

    prefix_owners = {}
    for k, v in file_info.items():
        prefix_owners[k] = v['package']

    for f in program_files:
        fi = file_info[f]
        if 'filetype' not in fi:
            continue
        filetype = fi['filetype']
        # path = join(run_prefix, f)
        # filetype = codefile_type(path)
        # if not filetype or filetype not in filetypes_for_platform[subdir.split('-')[0]]:
        #     continue
        if not filetype or filetype not in filetypes_for_platform[subdir.split('-')[0]]:
            continue
        needed = fi['libraries']['resolved']
        for needed_dso in needed:
            if (error_overlinking and
               not needed_dso.startswith('/') and
               not needed_dso.startswith(sysroot_sub) and
               not needed_dso.startswith(buildprefix_sub) and
               needed_dso not in prefix_owners and
               needed_dso not in files):
                in_whitelist = False
                if not build_is_host:
                    in_whitelist = any([fnmatch(needed_dso, w) for w in whitelist])
                if not in_whitelist:
                    print("  ERROR :: {} not in prefix_owners".format(needed_dso))

    # Should the whitelist be expanded before the 'not in prefix_owners' check?
    # i.e. Do we want to be able to use the whitelist to allow missing files in general? If so move this up to
    # the line before 'for needed_dso in needed'
    whitelist += missing_dso_whitelist or []

    _show_linking_messages(files, errors, file_info, build_prefix, run_prefix, pkg_name,
                           error_overlinking, runpath_whitelist, verbose, requirements_run, lib_packages,
                           lib_packages_used, whitelist, sysroots_files, sysroot_prefix, sysroot_sub, subdir)

    if lib_packages_used != lib_packages:
        info_prelude = "   INFO ({})".format(pkg_name)
        warn_prelude = "WARNING ({})".format(pkg_name)
        err_prelude = "  ERROR ({})".format(pkg_name)
        for lib in lib_packages - lib_packages_used:
            if package_nature[lib] == 'run-exports library':
                msg_prelude = err_prelude if error_overdepending else warn_prelude
            elif package_nature[lib] == 'plugin library':
                msg_prelude = info_prelude
            else:
                msg_prelude = warn_prelude
            _print_msg(errors, "{}: {} package {} in requirements/run but it is not used "
                               "(i.e. it is overdepending or perhaps statically linked? "
                               "If that is what you want then add it to `build/ignore_run_exports`)"
                               .format(msg_prelude, package_nature[lib], lib), verbose=verbose)
    if len(errors):
        if exception_on_error:
            runpaths_errors = [error for error in errors if re.match(r".*runpaths.*found in.*", error)]
            if len(runpaths_errors):
                raise RunPathError(runpaths_errors)
            overlinking_errors = [error for error in errors if re.match(r".*(overlinking|not found in|did not find).*", error)]
            if len(overlinking_errors):
                raise OverLinkingError(overlinking_errors)
            overdepending_errors = [error for error in errors if "overdepending" in error]
            if len(overdepending_errors):
                raise OverDependingError(overdepending_errors)
        else:
            sys.exit(1)

    if pkg_vendoring_key in vendoring_record:
        imports = vendoring_record[pkg_vendoring_key]
        return imports
    else:
        return dict()


def check_overlinking(m, files, host_prefix=None):
    if not host_prefix:
        host_prefix = m.config.host_prefix
    return check_overlinking_impl(m.get_value('package/name'),
                                  m.get_value('package/version'),
                                  m.get_value('build/string'),
                                  m.get_value('build/number'),
                                  m.config.target_subdir,
                                  m.get_value('build/ignore_run_exports'),
                                  [req.split(' ')[0] for req in m.meta.get('requirements', {}).get('run', [])],
                                  [req.split(' ')[0] for req in m.meta.get('requirements', {}).get('build', [])],
                                  [req.split(' ')[0] for req in m.meta.get('requirements', {}).get('host', [])],
                                  host_prefix,
                                  m.config.build_prefix,
                                  m.meta.get('build', {}).get('missing_dso_whitelist', []),
                                  m.meta.get('build', {}).get('runpath_whitelist', []),
                                  m.config.error_overlinking,
                                  m.config.error_overdepending,
                                  m.config.verbose,
                                  True,
                                  files,
                                  m.config.bldpkgs_dir,
                                  m.config.output_folder,
                                  m.config.channel_urls,
                                  m.config.variant['CONDA_BUILD_SYSROOT'] if (
                                          'CONDA_BUILD_SYSROOT' in m.config.variant and m.config.target_subdir == 'osx-64'
                                  ) else None)


def post_process_shared_lib(m, f, files, host_prefix=None):
    if not host_prefix:
        host_prefix = m.config.host_prefix
    path = os.path.join(host_prefix, f)
    codefile_t = codefile_type(path)
    if not codefile_t or path.endswith('.debug'):
        return
    rpaths = m.get_value('build/rpaths', ['lib'])
    if codefile_t == 'elffile':
        mk_relative_linux(f, host_prefix, rpaths=rpaths,
                          method=m.get_value('build/rpaths_patcher', None))
    elif codefile_t == 'machofile':
        mk_relative_osx(path, host_prefix, m.config.build_prefix, files=files, rpaths=rpaths)


def fix_permissions(files, prefix):
    print("Fixing permissions")
    for path in scandir(prefix):
        if path.is_dir():
            lchmod(path.path, 0o775)

    for f in files:
        path = join(prefix, f)
        st = os.lstat(path)
        old_mode = stat.S_IMODE(st.st_mode)
        new_mode = old_mode
        # broadcast execute
        if old_mode & stat.S_IXUSR:
            new_mode = new_mode | stat.S_IXGRP | stat.S_IXOTH
        # ensure user and group can write and all can read
        new_mode = new_mode | stat.S_IWUSR | stat.S_IWGRP | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH  # noqa
        if old_mode != new_mode:
            try:
                lchmod(path, new_mode)
            except (OSError, utils.PermissionError) as e:
                log = utils.get_logger(__name__)
                log.warn(str(e))


def post_build(m, files, build_python, host_prefix=None, is_already_linked=False):
    print('number of files:', len(files))

    if not host_prefix:
        host_prefix = m.config.host_prefix

    if not is_already_linked:
        for f in files:
            make_hardlink_copy(f, host_prefix)

    binary_relocation = m.binary_relocation()
    # If you have explicitly listed files for binary relocation and you are on Windows then
    # it should be presumed that you really need it to happen.
    if not m.config.target_subdir.startswith('win') or isinstance(binary_relocation, list):
        binary_relocation = m.binary_relocation()
        if not binary_relocation:
            print("Skipping binary relocation logic")
        osx_is_app = (m.config.target_subdir == 'osx-64' and
                      bool(m.get_value('build/osx_is_app', False)))
        check_symlinks(files, host_prefix, m.config.croot)
        prefix_files = utils.prefix_files(host_prefix)

        if not binary_relocation:
            print("Skipping binary relocation logic")

        for f in files:
            if f.startswith('bin/'):
                fix_shebang(f, prefix=host_prefix, build_python=build_python,
                            osx_is_app=osx_is_app)
            if binary_relocation is True or (isinstance(binary_relocation, list) and
                                             f in binary_relocation):
                post_process_shared_lib(m, f, prefix_files, host_prefix)
    check_overlinking(m, files, host_prefix)


def check_symlinks(files, prefix, croot):
    if readlink is False:
        return  # Not on Unix system
    msgs = []
    real_build_prefix = realpath(prefix)
    for f in files:
        path = join(real_build_prefix, f)
        if islink(path):
            link_path = readlink(path)
            real_link_path = realpath(path)
            # symlinks to binaries outside of the same dir don't work.  RPATH stuff gets confused
            #    because ld.so follows symlinks in RPATHS
            #    If condition exists, then copy the file rather than symlink it.
            if (not dirname(link_path) == dirname(real_link_path) and
                    codefile_type(f)):
                os.remove(path)
                utils.copy_into(real_link_path, path)
            elif real_link_path.startswith(real_build_prefix):
                # If the path is in the build prefix, this is fine, but
                # the link needs to be relative
                rp = relpath(real_link_path, dirname(path))
                if not link_path.startswith('.') and link_path != rp:
                    # Don't change the link structure if it is already a
                    # relative link. It's possible that ..'s later in the path
                    # can result in a broken link still, but we'll assume that
                    # such crazy things don't happen.
                    print("Making absolute symlink %s -> %s relative" % (f, link_path))
                    os.unlink(path)
                    os.symlink(rp, path)
            else:
                # Symlinks to absolute paths on the system (like /usr) are fine.
                if real_link_path.startswith(croot):
                    msgs.append("%s is a symlink to a path that may not "
                        "exist after the build is completed (%s)" % (f, link_path))

    if msgs:
        for msg in msgs:
            print("Error: %s" % msg, file=sys.stderr)
        sys.exit(1)


def make_hardlink_copy(path, prefix):
    """Hardlinks create invalid packages.  Copy files to break the link.
    Symlinks are OK, and unaffected here."""
    if not isabs(path):
        path = normpath(join(prefix, path))
    fn = basename(path)
    if os.lstat(path).st_nlink > 1:
        with TemporaryDirectory() as dest:
            # copy file to new name
            utils.copy_into(path, dest)
            # remove old file
            utils.rm_rf(path)
            # rename copy to original filename
            #   It is essential here to use copying (as opposed to os.rename), so that
            #        crossing volume boundaries works
            utils.copy_into(join(dest, fn), path)


def get_build_metadata(m):
    src_dir = m.config.work_dir
    if exists(join(src_dir, '__conda_version__.txt')):
        raise ValueError("support for __conda_version__ has been removed as of Conda-build 3.0."
              "Try Jinja templates instead: "
              "http://conda.pydata.org/docs/building/meta-yaml.html#templating-with-jinja")
    if exists(join(src_dir, '__conda_buildnum__.txt')):
        raise ValueError("support for __conda_buildnum__ has been removed as of Conda-build 3.0."
              "Try Jinja templates instead: "
              "http://conda.pydata.org/docs/building/meta-yaml.html#templating-with-jinja")
    if exists(join(src_dir, '__conda_buildstr__.txt')):
        raise ValueError("support for __conda_buildstr__ has been removed as of Conda-build 3.0."
              "Try Jinja templates instead: "
              "http://conda.pydata.org/docs/building/meta-yaml.html#templating-with-jinja")


def make_sysroot_path_list(sysroot, subdir, whitelist):
    '''

    :param sysroot: A real sysroot directory populated with DSOs of some sort matching glob_ext
    :param subdir: win-32, linux-64 etc
    :param glob_ext: *.dll or *.dylib* or *.so* or something, may want to make this a tuple?
    :param whitelist: A glob-style whitelist

    :return: a list of Paths for things that exist and a list of PurePaths for things that do not.
             Since this searches in live OS installations sometimes it can be slow, so we pre-bake them
             for macOS and Windows. Linux uses CDTs so dynamically searching is important (and should not
             be slow).
    '''
    glob_exts = {'win-32': '*.dll',
                 'win-64': '*.dll',
                 'osx-64': '*.dylib*'}

    if subdir in glob_exts:
        glob_ext = glob_exts[subdir]
    else:
        glob_ext = '*.so*'

    root = Path(sysroot)
    dsos_re = re.compile('(' + '|'.join('^' + translate(dso) + '$' for dso in whitelist) + ')',
                         re.IGNORECASE if not subdir.startswith('linux') else 0)
    matches = []
    exts = (glob_ext,)
    for ext in exts:
        for subp in root.rglob(ext):  # recursively iterate all items matching the glob pattern
            if subp.is_dir():
                continue
            rela = subp.relative_to(root).as_posix()
            if re.match(dsos_re, '/' + rela):
                matches.append(PurePath('/' + rela))
    # It might be sensible at this point to try to 'unbake' the result back to the glob that created it, or
    # do we just want a big old superset of all the DLLs we've ever seen that grows and grows?
    return tuple(matches)


def _native_subdir():
    if sys.platform == 'win32':
        subdir = 'win-64' if sys.maxsize > 2 ** 32 else 'win-32'
    elif sys.platform == 'darwin':
        subdir = 'osx-64'
    elif sys.platform.startswith('linux'):
        # TODO :: Other linuxes, and really, find some function that
        #         already does this, there must be several.
        subdir = 'linux-64'
    return subdir


def sysroot_path_list(subdir, sysroot=None, whitelist_forcing_rescan=None):
    '''
    Does the 'best thing' to get a sysroot path list given the sys.platform and
    subdir. When subdir is "linux-*", sysroot will always point to a proper sysroot
    (should it be multiple?)
    '''
    matches = None
    if (subdir.startswith('linux') or
            (_native_subdir() == subdir and whitelist_forcing_rescan)):
        if subdir.startswith('linux') and not whitelist_forcing_rescan:
            whitelist_forcing_rescan = ['**/*.so*']
        matches = make_sysroot_path_list(sysroot, subdir, whitelist_forcing_rescan)

    module_name = 'conda_build.post.baked_sysroot_pathlists'
    module_path = join(dirname(__file__), 'baked_sysroot_pathlists', subdir.replace('-', '_') + '.py')

    if not exists(module_path):
        return matches

    try:
        # Python 3
        import importlib.util
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        baked_sysroot_pathlists = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(baked_sysroot_pathlists)
    except:
        # Python 2
        from imp import load_source
        baked_sysroot_pathlists = load_source(module_name, module_path)

    # TODO :: Consider allowing multiple WHITELISTs per module?
    for entry in dir(baked_sysroot_pathlists):
        if 'WHITELIST' in entry:
            baked = getattr(baked_sysroot_pathlists, entry)
            break

    if matches:
        if matches != baked:
            print("WARNING :: Mismatch between sysroot files\nbaked: {}, found: {}".format(baked, matches))

    return baked if baked else matches


def bake_sys_platform_sysroot_path_list(sysroot=None):
    subdir = _native_subdir()
    if subdir.startswith('win'):
        if not sysroot:
            sysroot = os.environ['windir']
        whitelist = DEFAULT_WIN_WHITELIST
        baked_name = 'DEFAULT_WIN_WHITELIST_BAKED'
    elif subdir == 'osx-64':
        # This should really be run on whatever our lowest macOS version is (though
        # in the final version of this we'll pass sysroot=CONDA_BUILD_SYSROOT) or just
        # hard-code it.
        # If we go above 10.9 we need to pretend that tbd files are dylibs and do some
        # horrible swapping between them and system dylibs at some stage.
        if not sysroot:
            sysroot = '/opt/MacOSX10.9.sdk'
        whitelist = DEFAULT_MAC_WHITELIST
        baked_name = 'DEFAULT_MAC_WHITELIST_BAKED'
    else:
        print("Baking a sysroot path list for sys.platform={} is meaningless.".format(sys.platform))
        sys.exit(1)
    matches = make_sysroot_path_list(sysroot, subdir, whitelist)
    if len(matches):
        filename = Path(dirname(__file__)) / Path('baked_sysroot_pathlists') / Path(subdir.replace('-', '_') + '.py')
        try:
            os.makedirs(dirname(filename.absolute()))
        except:
            pass
        with open(filename, "w") as f:
            f.write("try:\n")
            f.write("    from pathlib2 import PurePath\n")
            f.write("except:\n")
            f.write("    from pathlib import PurePath\n")
            f.write("{} = (".format(baked_name))
            f.write(''.join("{spacing}PurePath('{as_posix}'),  # noqa\n".format(
                    as_posix=m.as_posix(),
                    spacing=' ' * (len(baked_name) + 4) if m != matches[0] else '')
                    for m in matches))
            f.write(")\n")


'''
if __name__ == 'conda_build.post' or __name__ == '__main__':
    bake_sys_platform_sysroot_path_list()
    # matches = make_sysroot_path_list('C:/Windows', 'win-64', DEFAULT_WIN_WHITELIST)
    # print(len(matches))
    # print(matches)
    # bake_sys_platform_sysroot_path_list()
    sysroot_files = sysroot_path_list('win-64', 'C:/Windows/System32', None)
    print(sysroot_files)
'''
