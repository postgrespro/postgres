toastapi = shared_module('toastapi',
  files('toastapi.c'),
  kwargs: contrib_mod_args,
)
contrib_targets += toastapi

install_data(
  'toastapi.control',
  'toastapi--1.0.sql',
  kwargs: contrib_data_args,
)

tests += {
  'name': 'toastapi',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'regress': {
    'sql': [
      'toastapi',
    ],
  },
}
