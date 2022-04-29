project(
  'openssl',
  'c',
  version: '1.1.1l',
  license: 'Apache-2.0',
  meson_version: '>= 0.55',
  default_options: [
    'warning_level=1',
  ],
)

library_version = '1.1.1'
library_soversion = '1.1'

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

asm_opt = get_option('asm')

if asm_opt.disabled()
  new_gas_or_nasm = false
  any_gas_or_nasm = false
else
  new_gas_or_nasm = (
    find_program('as', required: false, version: '>=2.26').found() or
    find_program('nasm', required: false, version: '>=2.11.8').found()
  )
  any_gas_or_nasm = (
    new_gas_or_nasm or
    find_program('as', required: false).found() or
    find_program('nasm', required: false).found()
  )
endif

if new_gas_or_nasm
  asm = 'asm'

  # Require AVX512IFMA supported. See
  # https://www.openssl.org/docs/man1.1.1/man3/OPENSSL_ia32cap.html
  # Currently crypto/poly1305/asm/poly1305-x86_64.pl requires AVX512IFMA.
  if host_machine.cpu_family() == 'ppc' and host_machine.system() == 'linux'
    arch_subdir = 'linux-ppc'
  elif host_machine.cpu_family() == 'ppc64' and host_machine.system() == 'linux' and host_machine.endian() == 'little'
    arch_subdir = 'linux-ppc64le'
  elif host_machine.cpu_family() == 'ppc64' and host_machine.system() == 'linux'
    arch_subdir = 'linux-ppc64'
  elif host_machine.cpu_family() == 's390x' and host_machine.system() == 'linux'
    arch_subdir = 'linux64-s390x'
  elif host_machine.cpu_family() == 'arm' and host_machine.system() in ['linux', 'android']
    arch_subdir = 'linux-armv4'
  elif host_machine.cpu_family() == 'aarch64' and host_machine.system() in ['linux', 'android']
    arch_subdir = 'linux-aarch64'
  elif host_machine.cpu_family() == 'aarch64' and host_machine.system() in ['dragonfly', 'freebsd', 'netbsd', 'openbsd']
    arch_subdir = 'BSD-generic64'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() in ['dragonfly', 'freebsd', 'netbsd', 'openbsd']
    arch_subdir = 'BSD-x86'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() in ['linux', 'android']
    arch_subdir = 'linux-elf'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() == 'darwin'
    arch_subdir = 'darwin-i386-cc'
  elif host_machine.cpu_family() == 'arm' and host_machine.system() == 'darwin'
    arch_subdir = 'darwin-armv7-cc'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() == 'qnx'
    arch_subdir = 'qnx-x86'
  elif host_machine.cpu_family() == 'arm' and host_machine.system() == 'qnx'
    arch_subdir = 'qnx-arm'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() == 'sunos'
    arch_subdir = 'solaris-x86-gcc'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() == 'windows'
    warning('x86 + windows combo does not support ASM yet, please contribute')
    asm = 'no-asm'
    # TODO: Port this for Windows and uncomment
    # arch_subdir = 'VC-WIN32'
    # asm = 'asm'
    #'rules': [
    #  {
    #    'rule_name': 'Assemble',
    #    'extension': 'asm',
    #    'inputs': [],
    #    'outputs': [
    #      '<(INTERMEDIATE_DIR)/<(RULE_INPUT_ROOT).obj',
    #    ],
    #    'action': [
    #      'nasm.exe',
    #      '-f win32',
    #      '-o', '<(INTERMEDIATE_DIR)/<(RULE_INPUT_ROOT).obj',
    #      '<(RULE_INPUT_PATH)',
    #    ],
    #  }
    #],
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() in ['dragonfly', 'freebsd', 'netbsd', 'openbsd']
    arch_subdir = 'BSD-x86_64'
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() == 'darwin'
    arch_subdir = 'darwin64-x86_64-cc'
  elif host_machine.cpu_family() == 'aarch64' and host_machine.system() == 'darwin'
    arch_subdir = 'darwin64-arm64-cc'
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() == 'sunos'
    arch_subdir = 'solaris64-x86_64-gcc'
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() == 'windows'
    warning('x86_64 + windows combo does not support ASM yet, please contribute')
    asm = 'no-asm'
    # TODO: Port this for Windows and uncomment
    # arch_subdir = 'VC-WIN64A'
    # asm = 'asm'
    #'rules': [
    #  {
    #    'rule_name': 'Assemble',
    #    'extension': 'asm',
    #    'inputs': [],
    #    'outputs': [
    #      '<(INTERMEDIATE_DIR)/<(RULE_INPUT_ROOT).obj',
    #    ],
    #    'action': [
    #      'nasm.exe',
    #      '-f win64',
    #      '-DNEAR',
    #      '-Ox',
    #      '-g',
    #      '-o', '<(INTERMEDIATE_DIR)/<(RULE_INPUT_ROOT).obj',
    #      '<(RULE_INPUT_PATH)',
    #    ],
    #  }
    #],
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() in ['linux', 'android']
    arch_subdir = 'linux-x86_64'
  elif host_machine.cpu_family() == 'mips' and host_machine.system() == 'linux'
    arch_subdir = 'linux-mips32'
  elif host_machine.cpu_family() == 'mips64' and host_machine.system() == 'linux'
    arch_subdir = 'linux64-mips64'
  else
    asm = 'no-asm'
  endif
elif any_gas_or_nasm
  asm = 'asm_avx2'

  if host_machine.cpu_family() == 'ppc' and host_machine.system() == 'linux'
    arch_subdir = 'linux-ppc'
  elif host_machine.cpu_family() == 'ppc64' and host_machine.system() == 'linux' and host_machine.endian() == 'little'
    arch_subdir = 'linux-ppc64le'
  elif host_machine.cpu_family() == 'ppc64' and host_machine.system() == 'linux'
    arch_subdir = 'linux-ppc64'
  elif host_machine.cpu_family() == 's390x' and host_machine.system() == 'linux'
    arch_subdir = 'linux64-s390x'
  elif host_machine.cpu_family() == 'arm' and host_machine.system() in ['linux', 'android']
    arch_subdir = 'linux-armv4'
  elif host_machine.cpu_family() == 'aarch64' and host_machine.system() in ['linux', 'android']
    arch_subdir = 'linux-aarch64'
  elif host_machine.cpu_family() == 'aarch64' and host_machine.system() in ['dragonfly', 'freebsd', 'netbsd', 'openbsd']
    arch_subdir = 'BSD-generic64'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() in ['dragonfly', 'freebsd', 'netbsd', 'openbsd']
    arch_subdir = 'BSD-x86'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() in ['linux', 'android']
    arch_subdir = 'linux-elf'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() == 'darwin'
    arch_subdir = 'darwin-i386-cc'
  elif host_machine.cpu_family() == 'arm' and host_machine.system() == 'darwin'
    arch_subdir = 'darwin-armv7-cc'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() == 'qnx'
    arch_subdir = 'qnx-x86'
  elif host_machine.cpu_family() == 'arm' and host_machine.system() == 'qnx'
    arch_subdir = 'qnx-arm'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() == 'sunos'
    arch_subdir = 'solaris-x86-gcc'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() == 'windows'
    warning('x86 + windows combo does not support ASM yet, please contribute')
    asm = 'no-asm'
    # TODO: Port this for Windows and uncomment
    # arch_subdir = 'VC-WIN32'
    # asm = 'asm_avx2'
    #'rules': [
    #  {
    #    'rule_name': 'Assemble',
    #    'extension': 'asm',
    #    'inputs': [],
    #    'outputs': [
    #      '<(INTERMEDIATE_DIR)/<(RULE_INPUT_ROOT).obj',
    #    ],
    #    'action': [
    #      'nasm.exe',
    #      '-f win32',
    #      '-o', '<(INTERMEDIATE_DIR)/<(RULE_INPUT_ROOT).obj',
    #      '<(RULE_INPUT_PATH)',
    #    ],
    #  }
    #],
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() in ['dragonfly', 'freebsd', 'netbsd', 'openbsd']
    arch_subdir = 'BSD-x86_64'
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() == 'darwin'
    arch_subdir = 'darwin64-x86_64-cc'
  elif host_machine.cpu_family() == 'aarch64' and host_machine.system() == 'darwin'
    arch_subdir = 'darwin64-arm64-cc'
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() == 'sunos'
    arch_subdir = 'solaris64-x86_64-gcc'
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() == 'windows'
    warning('x86_64 + windows combo does not support ASM yet, please contribute')
    asm = 'no-asm'
    # TODO: Port this for Windows and uncomment
    # arch_subdir = 'VC-WIN64A'
    # asm = 'asm_avx2'
    #'rules': [
    #  {
    #    'rule_name': 'Assemble',
    #    'extension': 'asm',
    #    'inputs': [],
    #    'outputs': [
    #      '<(INTERMEDIATE_DIR)/<(RULE_INPUT_ROOT).obj',
    #    ],
    #    'action': [
    #      'nasm.exe',
    #      '-f win64',
    #      '-DNEAR',
    #      '-Ox',
    #      '-g',
    #      '-o', '<(INTERMEDIATE_DIR)/<(RULE_INPUT_ROOT).obj',
    #      '<(RULE_INPUT_PATH)',
    #    ],
    #  }
    #],
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() == ['linux', 'android']
    arch_subdir = 'linux-x86_64'
  else
    asm = 'no-asm'
  endif
elif asm_opt.enabled()
  error('Neither GNU Assembler nor Netwide Assembler were found, cannot use use "asm=enabled" option')
else
  asm = 'no-asm'
endif

if asm == 'no-asm'
  defines += ['OPENSSL_NO_ASM']
  if host_machine.cpu_family() == 'ppc' and host_machine.system() == 'linux'
    arch_subdir = 'linux-ppc'
  elif host_machine.cpu_family() == 'ppc64' and host_machine.system() == 'linux' and host_machine.endian() == 'little'
    arch_subdir = 'linux-ppc64le'
  elif host_machine.cpu_family() == 'ppc64' and host_machine.system() == 'linux'
    arch_subdir = 'linux-ppc64'
  elif host_machine.cpu_family() == 's390x' and host_machine.system() == 'linux'
    arch_subdir = 'linux64-s390x'
  elif host_machine.cpu_family() == 'arm' and host_machine.system() in ['linux', 'android']
    arch_subdir = 'linux-armv4'
  elif host_machine.cpu_family() == 'aarch64' and host_machine.system() in ['linux', 'android']
    arch_subdir = 'linux-aarch64'
  elif host_machine.cpu_family() == 'aarch64' and host_machine.system() in ['dragonfly', 'freebsd', 'netbsd', 'openbsd']
    arch_subdir = 'BSD-generic64'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() in ['dragonfly', 'freebsd', 'netbsd', 'openbsd']
    arch_subdir = 'BSD-x86'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() in ['linux', 'android']
    arch_subdir = 'linux-elf'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() == 'darwin'
    arch_subdir = 'darwin-i386-cc'
  elif host_machine.cpu_family() == 'arm' and host_machine.system() == 'darwin'
    arch_subdir = 'darwin-armv7-cc'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() == 'qnx'
    arch_subdir = 'qnx-x86'
  elif host_machine.cpu_family() == 'arm' and host_machine.system() == 'qnx'
    arch_subdir = 'qnx-arm'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() == 'sunos'
    arch_subdir = 'solaris-x86-gcc'
  elif host_machine.cpu_family() == 'x86' and host_machine.system() == 'windows'
    arch_subdir = 'VC-WIN32'
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() in ['dragonfly', 'freebsd', 'netbsd', 'openbsd']
    arch_subdir = 'BSD-x86_64'
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() == 'darwin'
    arch_subdir = 'darwin64-x86_64-cc'
  elif host_machine.cpu_family() == 'aarch64' and host_machine.system() == 'darwin'
    arch_subdir = 'darwin64-arm64-cc'
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() == 'sunos'
    arch_subdir = 'solaris64-x86_64-gcc'
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() == 'windows'
    arch_subdir = 'VC-WIN64A'
  elif host_machine.cpu_family() == 'aarch64' and host_machine.system() == 'windows'
    arch_subdir = 'VC-WIN64-ARM'
  elif host_machine.cpu_family() == 'x86_64' and host_machine.system() == 'linux'
    arch_subdir = 'linux-x86_64'
  elif host_machine.cpu_family() == 'mips' and host_machine.system() == 'linux'
    arch_subdir = 'linux-mips32'
  elif host_machine.cpu_family() == 'mips64' and host_machine.system() == 'linux'
    arch_subdir = 'linux64-mips64'
  else
    error('Unsupported arch+OS combo: ' + host_machine.cpu_family() + ' + ' + host_machine.system())
  endif

  message('OpenSSL is configured without ASM support')
else
  message('OpenSSL is configured with ASM support')
endif

subdir('generated-config/archs' / arch_subdir / asm)

# Build options specific to OS, engines are disabled on purpose for the same reasons as `OPENSSL_NO_HW` above
if host_machine.system() == 'windows'
  defines += [
    ## default of Win. See INSTALL in openssl repo.
    'OPENSSLDIR="C:\\Program Files\\Common Files\\SSL"',
    'ENGINESDIR="NUL"',
    'OPENSSL_SYS_WIN32', 'WIN32_LEAN_AND_MEAN', 'L_ENDIAN',
    '_CRT_SECURE_NO_DEPRECATE', 'UNICODE', '_UNICODE',
  ]
  if compiler.get_id() == 'msvc'
    c_args += [
      '-wd4090', '-Gs0', '-GF', '-Gy', '-nologo',
    ]
  endif
elif host_machine.system() == 'darwin'
  defines += [
    'OPENSSLDIR="/System/Library/OpenSSL/"',
    'ENGINESDIR="/dev/null"',
  ]
  c_args += [
    '-Wno-missing-field-initializers',
  ]
elif host_machine.system() == 'sunos'
  defines += [
   'OPENSSLDIR="/etc/ssl"',
   'ENGINESDIR="/dev/null"',
   '__EXTENSIONS__'
 ]
else
  # linux and others
  defines += [
    'OPENSSLDIR="/etc/ssl"',
    'ENGINESDIR="/dev/null"',
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
  # MSVC fails with "ERROR: C static library 'ws2_32' not found" when `static` is specified at all
  if compiler.get_id() == 'msvc'
    dependencies += [
      compiler.find_library(library),
    ]
  else
    dependencies += [
      compiler.find_library(
        library,
        static: get_option('default_library') == 'static',
      ),
    ]
  endif
endforeach

# We may need to add some defines for static builds
if get_option('default_library') == 'static'
  defines += [
    'OSSL_CRYPTO_DSO_CONF_H',
    'DSO_NONE',
    'DSO_EXTENSION=.so',
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
  'asn1.h',
  'asn1_mac.h',
  'asn1err.h',
  'asn1t.h',
  'async.h',
  'asyncerr.h',
  'bio.h',
  'bioerr.h',
  'blowfish.h',
  'bn.h',
  'bnerr.h',
  'buffer.h',
  'buffererr.h',
  'camellia.h',
  'cast.h',
  'cmac.h',
  'cms.h',
  'cmserr.h',
  'comp.h',
  'comperr.h',
  'conf.h',
  'conf_api.h',
  'conferr.h',
  'crypto.h',
  'cryptoerr.h',
  'ct.h',
  'cterr.h',
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
  'engine.h',
  'engineerr.h',
  'err.h',
  'evp.h',
  'evperr.h',
  'hmac.h',
  'idea.h',
  'kdf.h',
  'kdferr.h',
  'lhash.h',
  'md2.h',
  'md4.h',
  'md5.h',
  'mdc2.h',
  'modes.h',
  'obj_mac.h',
  'objects.h',
  'objectserr.h',
  'ocsp.h',
  'ocsperr.h',
  'opensslv.h',
  'ossl_typ.h',
  'pem.h',
  'pem2.h',
  'pemerr.h',
  'pkcs12.h',
  'pkcs12err.h',
  'pkcs7.h',
  'pkcs7err.h',
  'rand.h',
  'rand_drbg.h',
  'randerr.h',
  'rc2.h',
  'rc4.h',
  'rc5.h',
  'ripemd.h',
  'rsa.h',
  'rsaerr.h',
  'safestack.h',
  'seed.h',
  'sha.h',
  'srp.h',
  'srtp.h',
  'ssl.h',
  'ssl2.h',
  'ssl3.h',
  'sslerr.h',
  'stack.h',
  'store.h',
  'storeerr.h',
  'symhacks.h',
  'tls1.h',
  'ts.h',
  'tserr.h',
  'txt_db.h',
  'ui.h',
  'uierr.h',
  'whrlpool.h',
  'x509.h',
  'x509_vfy.h',
  'x509err.h',
  'x509v3.h',
  'x509v3err.h',
]
public_headers = []
foreach h : public_header_names
  public_headers += 'include' / 'openssl' / h
endforeach
foreach d : openssl_include_directories
  if d.endswith('include')
    public_headers += d + '/openssl/opensslconf.h'
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
  variables: ['enginesdir=${libdir}/engines-1.1'],
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

cli_option = get_option('cli')
if cli_option.auto()
  cli_enabled = not meson.is_subproject()
else
  cli_enabled = cli_option.enabled()
endif
if cli_enabled
  openssl_cli = executable(
    'openssl',
    dependencies: dependencies + [openssl_dep],
    sources: openssl_cli_sources,
    include_directories: internal_incdirs,
    c_args: c_args,
    install: true,
  )
endif
