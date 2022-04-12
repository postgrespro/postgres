bytea_toaster = shared_module('bytea_toaster',
  files('bytea_toaster.c'),
  kwargs: contrib_mod_args,
)
contrib_targets += bytea_toaster

install_data(
  'bytea_toaster.control',
  'bytea_toaster--1.0.sql',
  kwargs: contrib_data_args,
)

tests += {
  'name': 'bytea_toaster',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'regress': {
    'sql': [
      'bytea_toaster',
    ],
  },
}
