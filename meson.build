project(
  'openssl',
  'c',
  version: '3.0.7',
  license: 'Apache-2.0',
  meson_version: '>= 0.64',
  default_options: [
    'warning_level=1',
  ],
)

library_version = '3.0.7'
library_soversion = '3'

# Make sure to generate configs in case they are not already
fs = import('fs')
if not fs.exists('generated-config')
  message('Generating OpenSSL configs...')
  run_command(
    'generator.sh',
    check: true,
    env: ['OPENSSL_VERSION=' + meson.project_version()],
  )
endif

compiler = meson.get_compiler('c')

if compiler.get_id() == 'msvc'
  add_project_arguments('/wd4133', language: 'c')
endif

dependencies = [
  # TODO: Make this optionally added once we have threading configurable via options
  dependency('threads'),
]
defines = [
  # Compile out hardware engines. Most are stubs that dynamically load
  # the real driver but that poses a security liability when an attacker
  # is able to create a malicious DLL in one of the default search paths.
  'OPENSSL_NO_HW',
]
c_args = []

is_bsd = host_machine.system() in ['dragonfly', 'freebsd', 'netbsd', 'openbsd']
is_darwin = host_machine.system() == 'darwin'
is_linux = host_machine.system() in ['linux', 'android']
is_qnx = host_machine.system() == 'qnx'
is_sunos = host_machine.system() == 'sunos'
is_windows = host_machine.system() == 'windows'

is_x86 = host_machine.cpu_family() == 'x86'
is_x86_64 = host_machine.cpu_family() == 'x86_64'
is_aarch64 = host_machine.cpu_family() == 'aarch64'
is_mips = host_machine.cpu_family() == 'mips'
is_mips64 = host_machine.cpu_family() == 'mips64'
is_s390x = host_machine.cpu_family() == 's390x'
is_arm = host_machine.cpu_family() == 'arm'
is_ppc = host_machine.cpu_family() == 'ppc'
is_ppc64 = host_machine.cpu_family() == 'ppc64'
is_riskv64 = host_machine.cpu_family() == 'riscv64'

asm_opt = get_option('asm')
if asm_opt.allowed() and compiler.get_id() == 'msvc' and (is_x86 or is_x86_64)
  gas_or_nasm = add_languages('nasm', native: false, required: asm_opt)
  asm_preprocessing_needed = true
else
  gas_or_nasm = asm_opt.allowed()
  asm_preprocessing_needed = false
endif

if gas_or_nasm
  asm = 'asm'

  if is_bsd
    if is_x86
      arch_subdir = 'BSD-x86'
    elif is_x86_64
      arch_subdir = 'BSD-x86_64'
    elif is_aarch64
      arch_subdir = 'BSD-aarch64'
    else
      asm = 'no-asm'
    endif
  elif is_darwin
    if is_aarch64
      arch_subdir = 'darwin64-arm64-cc'
    elif is_x86_64
      arch_subdir = 'darwin64-x86_64-cc'
    elif is_arm
      arch_subdir = 'darwin-armv7-cc'
    elif is_x86
      arch_subdir = 'darwin-i386-cc'
    else
      asm = 'no-asm'
    endif
  elif is_linux
    if is_mips64
      arch_subdir = 'linux64-mips64'
    elif is_s390x
      arch_subdir = 'linux64-s390x'
    elif is_aarch64
      arch_subdir = 'linux-aarch64'
    elif is_arm
      arch_subdir = 'linux-armv4'
    elif is_mips
      arch_subdir = 'linux-mips32'
    elif is_ppc
      arch_subdir = 'linux-ppc'
    elif is_ppc64 and host_machine.endian() == 'big'
      arch_subdir = 'linux-ppc64'
    elif is_ppc64
      arch_subdir = 'linux-ppc64le'
    elif is_x86
      arch_subdir = 'linux-x86'
    elif is_x86_64
      arch_subdir = 'linux-x86_64'
    else
      asm = 'no-asm'
    endif
  elif is_qnx
    if is_x86
      arch_subdir = 'qnx-x86'
    else
      asm = 'no-asm'
    endif
  elif is_sunos
    if is_x86_64
      arch_subdir = 'solaris64-x86_64-gcc'
    elif is_x86
      arch_subdir = 'solaris-x86-gcc'
    else
      asm = 'no-asm'
    endif
  elif is_windows
    if is_x86
      arch_subdir = 'VC-WIN32'
    elif is_x86_64
      arch_subdir = 'VC-WIN64A'
    else
      asm = 'no-asm'
    endif
  else
    asm = 'no-asm'
  endif
else
  asm = 'no-asm'
endif

if asm == 'no-asm'
  defines += ['OPENSSL_NO_ASM']
  error_message = 'Unsupported arch+OS combo: ' + host_machine.cpu_family() + ' + ' + host_machine.system()

  if is_bsd
    if is_x86
      arch_subdir = 'BSD-x86'
    elif is_x86_64
      arch_subdir = 'BSD-x86_64'
    elif is_aarch64
      arch_subdir = 'BSD-generic64'
    else
      error(error_message)
    endif
  elif is_darwin
    if is_aarch64
      arch_subdir = 'darwin64-arm64-cc'
    elif is_x86_64
      arch_subdir = 'darwin64-x86_64-cc'
    elif is_arm
      arch_subdir = 'darwin-armv7-cc'
    elif is_x86
      arch_subdir = 'darwin-i386-cc'
    else
      error(error_message)
    endif
  elif is_linux
    if is_mips64
      arch_subdir = 'linux64-mips64'
    elif is_riskv64
      arch_subdir = 'linux64-riscv64'
    elif is_s390x
      arch_subdir = 'linux64-s390x'
    elif is_aarch64
      arch_subdir = 'linux-aarch64'
    elif is_arm
      arch_subdir = 'linux-armv4'
    elif is_mips
      arch_subdir = 'linux-mips32'
    elif is_ppc
      arch_subdir = 'linux-ppc'
    elif is_ppc64 and host_machine.endian() == 'big'
      arch_subdir = 'linux-ppc64'
    elif is_ppc64
      arch_subdir = 'linux-ppc64le'
    elif is_x86
      arch_subdir = 'linux-x86'
    elif is_x86_64
      arch_subdir = 'linux-x86_64'
    else
      error(error_message)
    endif
  elif is_qnx
    if is_arm
      arch_subdir = 'qnx-arm'
    elif is_x86
      arch_subdir = 'qnx-x86'
    else
      asm = 'no-asm'
    endif
  elif is_sunos
    if is_x86_64
      arch_subdir = 'solaris64-x86_64-gcc'
    elif is_x86
      arch_subdir = 'solaris-x86-gcc'
    else
      error(error_message)
    endif
  elif is_windows
    if is_x86
      arch_subdir = 'VC-WIN32'
    elif is_aarch64
      arch_subdir = 'VC-WIN64-ARM'
    elif is_x86_64
      arch_subdir = 'VC-WIN64A'
    else
      error(error_message)
    endif
  else
    error(error_message)
  endif

  message('OpenSSL is configured without ASM support')
else
  message('OpenSSL is configured with ASM support')
endif

subdir('generated-config/archs' / arch_subdir / asm)

if asm_preprocessing_needed
  c_sources = []
  asm_sources = []
  foreach s : libcrypto_sources
    if s.endswith('.asm')
      asm_sources += s
    else
      c_sources += s
    endif
  endforeach
  libcrypto_sources = [c_sources, compiler.preprocess(asm_sources, output: '@PLAINNAME@')]
endif

# Build options specific to OS, engines are disabled on purpose for the same reasons as `OPENSSL_NO_HW` above
if is_windows
  defines += [
    ## default of Win. See INSTALL in openssl repo.
    'OPENSSLDIR="C:\\Program Files\\Common Files\\SSL"',
    'ENGINESDIR="NUL"',
    'MODULESDIR="NUL"',
    'OPENSSL_SYS_WIN32', 'WIN32_LEAN_AND_MEAN', 'L_ENDIAN',
    '_CRT_SECURE_NO_DEPRECATE', 'UNICODE', '_UNICODE',
  ]
  if compiler.get_id() == 'msvc'
    c_args += [
      '-wd4090', '-Gs0', '-GF', '-Gy', '-nologo',
    ]
  endif
elif is_darwin
  defines += [
    'OPENSSLDIR="/System/Library/OpenSSL/"',
    'ENGINESDIR="/dev/null"',
    'MODULESDIR="/dev/null"',
  ]
  c_args += [
    '-Wno-missing-field-initializers',
  ]
elif is_sunos
  defines += [
   'OPENSSLDIR="/etc/ssl"',
   'ENGINESDIR="/dev/null"',
   'MODULESDIR="/dev/null"',
   '__EXTENSIONS__'
 ]
else
  # Linux and others
  defines += [
    'OPENSSLDIR="/etc/ssl"',
    'ENGINESDIR="/dev/null"',
    'MODULESDIR="/dev/null"',
  ]
  c_args += [
    '-Wno-missing-field-initializers',
  ]
  if compiler.get_id() != 'clang'
    c_args += [
      '-Wno-old-style-declaration',
    ]
  endif
endif

foreach library : openssl_libraries
  dependencies += compiler.find_library(library)
endforeach

# We may need to add some defines for static builds
if get_option('default_library') == 'static'
  defines += [
    'OSSL_CRYPTO_DSO_CONF_H',
    'DSO_NONE',
    'DSO_EXTENSION=".so"',
    'OPENSSL_NO_DSO',
  ]
endif

foreach define : defines + openssl_defines
  c_args += ['-D' + define]
endforeach

c_args += openssl_cflags

internal_incdirs = [
  'include',
  'crypto',
  'crypto/modes',
  'crypto/ec/curve448',
  'crypto/ec/curve448/arch_32',
  'providers/common/include',
  'providers/implementations/include',
]
internal_incdirs += openssl_include_directories

public_incdirs = [
  'include',
]
foreach d : openssl_include_directories
  if d.endswith('include')
    public_incdirs += d
    break
  endif
endforeach

public_header_names = [
  'aes.h',
  'asn1_mac.h',
  'asn1err.h',
  'async.h',
  'asyncerr.h',
  'bioerr.h',
  'blowfish.h',
  'bn.h',
  'bnerr.h',
  'buffer.h',
  'buffererr.h',
  'camellia.h',
  'cast.h',
  'cmac.h',
  'cmp_util.h',
  'cmperr.h',
  'cmserr.h',
  'comp.h',
  'comperr.h',
  'conf_api.h',
  'conferr.h',
  'conftypes.h',
  'core.h',
  'core_dispatch.h',
  'core_names.h',
  'core_object.h',
  'crmferr.h',
  'cryptoerr.h',
  'cryptoerr_legacy.h',
  'cterr.h',
  'decoder.h',
  'decodererr.h',
  'des.h',
  'dh.h',
  'dherr.h',
  'dsa.h',
  'dsaerr.h',
  'dtls1.h',
  'e_os2.h',
  'ebcdic.h',
  'ec.h',
  'ecdh.h',
  'ecdsa.h',
  'ecerr.h',
  'encoder.h',
  'encodererr.h',
  'engine.h',
  'engineerr.h',
  'esserr.h',
  'evp.h',
  'evperr.h',
  'fips_names.h',
  'hmac.h',
  'http.h',
  'httperr.h',
  'idea.h',
  'kdf.h',
  'kdferr.h',
  'macros.h',
  'md2.h',
  'md4.h',
  'md5.h',
  'mdc2.h',
  'modes.h',
  'obj_mac.h',
  'objects.h',
  'objectserr.h',
  'ocsperr.h',
  'opensslconf.h',
  'ossl_typ.h',
  'param_build.h',
  'params.h',
  'pem.h',
  'pem2.h',
  'pemerr.h',
  'pkcs12err.h',
  'pkcs7err.h',
  'prov_ssl.h',
  'proverr.h',
  'provider.h',
  'rand.h',
  'randerr.h',
  'rc2.h',
  'rc4.h',
  'rc5.h',
  'ripemd.h',
  'rsa.h',
  'rsaerr.h',
  'seed.h',
  'self_test.h',
  'sha.h',
  'srtp.h',
  'ssl2.h',
  'ssl3.h',
  'sslerr.h',
  'sslerr_legacy.h',
  'stack.h',
  'store.h',
  'storeerr.h',
  'symhacks.h',
  'tls1.h',
  'trace.h',
  'ts.h',
  'tserr.h',
  'txt_db.h',
  'types.h',
  'uierr.h',
  'whrlpool.h',
  'x509err.h',
  'x509v3err.h',
]
public_header_names_generated = [
  'asn1.h',
  'asn1t.h',
  'bio.h',
  'cmp.h',
  'cms.h',
  'conf.h',
  'configuration.h',
  'crmf.h',
  'crypto.h',
  'ct.h',
  'err.h',
  'ess.h',
  'fipskey.h',
  'lhash.h',
  'ocsp.h',
  'opensslv.h',
  'pkcs12.h',
  'pkcs7.h',
  'safestack.h',
  'srp.h',
  'ssl.h',
  'ui.h',
  'x509.h',
  'x509v3.h',
  'x509_vfy.h',
]
public_headers = []
foreach h : public_header_names
  public_headers += 'include' / 'openssl' / h
endforeach
foreach d : openssl_include_directories
  if d.endswith('asm/include')
    foreach h : public_header_names_generated
      public_headers += d / 'openssl' / h
    endforeach
    break
  endif
endforeach
install_headers(public_headers, subdir: 'openssl')

libcrypto_lib = library('crypto',
  version: library_version,
  soversion: library_soversion,
  dependencies: dependencies,
  sources: libcrypto_sources,
  include_directories: internal_incdirs,
  c_args: c_args,
  install: true,
)

libcrypto_dep = declare_dependency(
  include_directories: public_incdirs,
  dependencies: dependencies,
  link_with: libcrypto_lib,
)

pkg = import('pkgconfig')
pkg.generate(libcrypto_lib,
  filebase: 'libcrypto',
  name: 'OpenSSL-libcrypto',
  description: 'OpenSSL cryptography library',
  variables: ['enginesdir=${libdir}/engines-3'],
)

meson.override_dependency('libcrypto', libcrypto_dep)

libssl_lib = library('ssl',
  version: library_version,
  soversion: library_soversion,
  dependencies: dependencies + [libcrypto_dep],
  sources: libssl_sources,
  include_directories: internal_incdirs,
  c_args: c_args,
  install: true,
)

libssl_dep = declare_dependency(
  include_directories: public_incdirs,
  dependencies: dependencies + [libcrypto_dep],
  link_with: libssl_lib,
)

pkg.generate(libssl_lib,
  filebase: 'libssl',
  name: 'OpenSSL-libssl',
  description: 'Secure Sockets Layer and cryptography libraries',
)

meson.override_dependency('libssl', libssl_dep)

openssl_dep = declare_dependency(
  dependencies: [libcrypto_dep, libssl_dep],
)

pkg.generate(
  filebase: 'openssl',
  name: 'OpenSSL',
  description: 'Secure Sockets Layer and cryptography libraries and tools',
  requires: ['libssl', 'libcrypto']
)

meson.override_dependency('openssl', openssl_dep)

openssl_cli_directories = internal_incdirs + [
  'apps/include'
]

cli_opt = get_option('cli').disable_auto_if(meson.is_subproject()).allowed()

openssl_cli = executable(
  'openssl',
  build_by_default: cli_opt,
  dependencies: dependencies + [openssl_dep],
  sources: openssl_cli_sources,
  include_directories: openssl_cli_directories,
  c_args: c_args,
  install: cli_opt,
)
