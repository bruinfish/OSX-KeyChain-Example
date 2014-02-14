# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
APPNAME = 'osx-keychain-example'
VERSION = '0.1'

from waflib import Build, Logs, Utils, Task, TaskGen, Configure;

def options(opt):
    opt.load('compiler_c compiler_cxx c_osx')
    opt.load('cryptopp boost', tooldir=['.waf-tools'])

    opt.add_option('--debug',action='store_true',default=False,dest='debug',help='''debugging mode''')
    opt.add_option('--with-log4cxx', action='store_true',default=False,dest='log4cxx',
                   help='''Compile with log4cxx logging support''')


def configure(conf):
    conf.load('compiler_c compiler_cxx boost c_osx cryptopp')

    if conf.options.debug:
        conf.define ('_DEBUG', 1)
        flags = ['-O0',
                 '-Wall',
                 # '-Werror',
                 '-Wno-unused-variable',
                 '-g3',
                 '-Wno-unused-private-field', # only clang supports
                 '-fcolor-diagnostics',       # only clang supports
                 '-Qunused-arguments',        # only clang supports
                 '-Wno-tautological-compare', # suppress warnings from CryptoPP
                 '-Wno-unused-function',      # another annoying warning from CryptoPP

                 '-Wno-deprecated-declarations',
                 ]

        conf.add_supported_cxxflags (cxxflags = flags)
    else:
        flags = ['-O3', '-g', '-Wno-tautological-compare', '-Wno-unused-function', '-Wno-deprecated-declarations']
        conf.add_supported_cxxflags (cxxflags = flags)

    if Utils.unversioned_sys_platform () == "darwin":
        conf.check_cxx(framework_name='CoreFoundation', uselib_store='OSX_COREFOUNDATION', mandatory=True)
        conf.check_cxx(framework_name='CoreServices', uselib_store='OSX_CORESERVICES', mandatory=True)
        conf.check_cxx(framework_name='Security',   uselib_store='OSX_SECURITY',   define_name='HAVE_SECURITY',
                       use="OSX_COREFOUNDATION", mandatory=True)
        conf.define('HAVE_OSX_SECURITY', 1)

    if conf.options.log4cxx:
        conf.check_cfg(package='liblog4cxx', args=['--cflags', '--libs'], uselib_store='LOG4CXX', mandatory=True)
        conf.define ("HAVE_LOG4CXX", 1)

    conf.check_cryptopp(path=conf.options.cryptopp_dir, mandatory=True)
        
    conf.check_boost(lib='system filesystem date_time iostreams regex program_options')

    conf.write_config_header('config.h')

def build(bld):
     for app in bld.path.ant_glob (['*.cc']):
        name = str(app)[:-len(".cc")]
        bld.program (
            target = name,
            features = ['cxx'],
            source = [app],
            use = 'BOOST OSX_COREFOUNDATION OSX_CORESERVICES OSX_SECURITY LOG4CXX CRYPTOPP',
            includes = ".",
            )

@Configure.conf
def add_supported_cxxflags(self, cxxflags):
    """
    Check which cxxflags are supported by compiler and add them to env.CXXFLAGS variable
    """
    self.start_msg('Checking allowed flags for c++ compiler')

    supportedFlags = []
    for flag in cxxflags:
        if self.check_cxx (cxxflags=[flag], mandatory=False):
            supportedFlags += [flag]

    self.end_msg (' '.join (supportedFlags))
    self.env.CXXFLAGS += supportedFlags
