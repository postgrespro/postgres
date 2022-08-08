dummy_toaster = shared_module('dummy_toaster',
  files('dummy_toaster.c'),
  kwargs: contrib_mod_args,
)
contrib_targets += dummy_toaster

install_data(
  'dummy_toaster.control',
  'dummy_toaster--1.0.sql',
  kwargs: contrib_data_args,
)

tests += {
  'name': 'dummy_toaster',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'regress': {
    'sql': [
      'dummy_toaster',
    ],
  },
}
