

add_executable(test_vk_raw2json test_vk_raw2json.cpp)
target_link_libraries(test_vk_raw2json ethsnarks_common)


add_executable(test_shootout test_shootout.cpp)
target_link_libraries(test_shootout snark)

add_executable(test_load_proofkey test_load_proofkey.cpp)
target_link_libraries(test_load_proofkey ethsnarks_common)


add_executable(test_shamir_poly test_shamir_poly.cpp)
target_link_libraries(test_shamir_poly ethsnarks_common)


add_executable(test_sha256_full_gadget test_sha256_full_gadget.cpp)
target_link_libraries(test_sha256_full_gadget ethsnarks_common)


add_executable(test_proof_raw2json test_proof_raw2json.cpp)
target_link_libraries(test_proof_raw2json ethsnarks_common)


add_executable(test_field_packing test_field_packing.cpp)
target_link_libraries(test_field_packing ethsnarks_common)


add_executable(test_merkle_tree test_merkle_tree.cpp)
target_link_libraries(test_merkle_tree ethsnarks_common)


add_executable(test_hashpreimage test_hashpreimage.cpp)
target_link_libraries(test_hashpreimage ethsnarks_common)


add_executable(test_one_of_n test_one_of_n.cpp)
target_link_libraries(test_one_of_n ethsnarks_common)


add_executable(test_longsightl test_longsightl.cpp)
target_link_libraries(test_longsightl ethsnarks_common)


add_executable(test_longsightl_hash_mp test_longsightl_hash_mp.cpp)
target_link_libraries(test_longsightl_hash_mp ethsnarks_common)

