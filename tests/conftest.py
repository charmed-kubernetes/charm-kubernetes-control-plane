import charms.unit_test


charms.unit_test.patch_reactive()
charms.unit_test.patch_module('charms.coordinator')
charms.unit_test.patch_module('charms.leadership')
