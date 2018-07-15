/*    
    copyright 2018 to the Semaphore Authors

    This file is part of Semaphore.

    Semaphore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Semaphore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Semaphore.  If not, see <https://www.gnu.org/licenses/>.
*/


#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

//hash

#include <sha256/sha256_ethereum.cpp>
#include <export.cpp>
#include "miximus.hpp"
//key gen 
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key


typedef libff::alt_bn128_pp ppT;


#include <libsnark/gadgetlib1/gadget.hpp>

#include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>

namespace libsnark {
template<>
class pairing_selector<libff::alt_bn128_pp> {
public:
    typedef libff::alt_bn128_pp other_curve_type;
    // Fqe_variable = G1
    // Fqk_variable = G2 ?
};
}

using namespace libsnark;
using namespace libff;

typedef sha256_ethereum HashT;

template<typename FieldT, typename HashT>
class Miximus {
public:

    const size_t digest_len = HashT::get_digest_len();
    protoboard<FieldT> pb;
    pb_variable<FieldT> ZERO;

    // input unpacking
    std::shared_ptr<multipacking_gadget<FieldT> > unpacker;
    pb_variable_array<FieldT> packed_inputs;
    pb_variable_array<FieldT> unpacked_inputs;

    // input variables
    std::shared_ptr<digest_variable<FieldT> > signal;

    // local state
    std::shared_ptr<sha256_ethereum> input_hash;
    std::shared_ptr<block_variable<FieldT> > input_variable;
    std::shared_ptr<digest_variable<FieldT> > input_digest;

    pb_variable_array<FieldT> member_scalars;
    std::shared_ptr<G1_variable<ppT> > member_public;
    std::shared_ptr<G1_variable<ppT> > G1_ONE;
    std::shared_ptr<G1_multiscalar_mul_gadget<ppT> > member_mult;

    Miximus() {
        // 
        int num_input_vars = 1;
        packed_inputs.allocate(pb, num_input_vars + 1, "packed");
        pb.set_input_sizes(num_input_vars + 1);

        ZERO.allocate(pb, "ZERO");
        pb.val(ZERO) = 0;

        // Input variables
        signal.reset(new digest_variable<FieldT>(pb, 256, "signal"));

        // State variables
        input_digest.reset(new digest_variable<FieldT>(pb, 256, "input_digest"));

        // Unpack the inputs
        // Add more inputs here
        unpacked_inputs.insert(unpacked_inputs.end(), signal->bits.begin(), signal->bits.end());

        unpacker.reset(new multipacking_gadget<FieldT>(
            pb,
            unpacked_inputs,
            packed_inputs,
            FieldT::capacity(),
            "unpacker"
        ));


        // SHA256(signal, signal)
        input_variable.reset(new block_variable<FieldT>(pb, *signal, *signal, "input_variable"));
        input_hash.reset(new sha256_ethereum(
            pb, SHA256_block_size, *input_variable, *input_digest, "input_hash"
        ));


        // multiply(G1, signal)
        member_public.reset(new G1_variable<ppT>(pb, "member_public"));
        member_scalars.allocate(pb, 1, "member_scalars");
        std::vector<G1_variable<ppT> > member_points;

        member_mult.reset(new G1_multiscalar_mul_gadget<ppT>(pb,
            G1_ONE,
            member_scalars,
            FieldT::size_in_bits(),
            member_points,
            member_public, // result
            "member_mult"
        ));


        // generate constraints
        unpacker->generate_r1cs_constraints(true);
        generate_r1cs_equals_const_constraint<FieldT>(pb, ZERO, FieldT::zero(), "ZERO");

        // Input variables
        signal->generate_r1cs_constraints();

        // Functions
        input_hash->generate_r1cs_constraints(true);
        member_mult->generate_r1cs_constraints();

        printf("number of constraints is = %zu\n", pb.num_constraints());
    }

    void writeKeysToFile(char* pk , char* vk) {
        r1cs_constraint_system<FieldT> constraints = this->pb.get_constraint_system();

        r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair = generateKeypair(this->pb.get_constraint_system());

        //save keys
        vk2json(keypair, vk);

        writeToFile(pk, keypair.pk);
        writeToFile("../zksnark_element/vk.raw", keypair.vk); 
    }

    char* prove(libff::bit_vector _signal, 
                char* pk , bool isInt)
    { 

        signal->generate_r1cs_witness(_signal);

        input_hash->generate_r1cs_witness();  


        unpacker->generate_r1cs_witness_from_bits();
            
        r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair;
        keypair.pk = loadFromFile<r1cs_ppzksnark_proving_key<alt_bn128_pp>> (pk);

        pb.primary_input();
        pb.auxiliary_input();

        r1cs_primary_input <FieldT> primary_input = pb.primary_input();
        std::cout << "primary_input " << primary_input;
        r1cs_auxiliary_input <FieldT> auxiliary_input = pb.auxiliary_input();
        r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_prover<libff::alt_bn128_pp>(keypair.pk, primary_input, auxiliary_input);

        auto json = proof_to_json (proof, primary_input, isInt);     

        auto result = new char[json.size()];
        memcpy(result, json.c_str(), json.size() + 1);     
        return result; 

    }
};

void genKeys(char* pkOutput, char* vkOuput) {

    libff::alt_bn128_pp::init_public_params();
    Miximus<FieldT, sha256_ethereum> c;
    c.writeKeysToFile(pkOutput, vkOuput);
}

bool verify( char* vk, char* _g_A_0, char* _g_A_1, char* _g_A_2 ,  char* _g_A_P_0, char* _g_A_P_1, char* _g_A_P_2, 
             char* _g_B_1, char* _g_B_0, char* _g_B_3, char* _g_B_2, char* _g_B_5 , char* _g_B_4, char* _g_B_P_0, char* _g_B_P_1, char* _g_B_P_2,
             char* _g_C_0, char* _g_C_1, char* _g_C_2, char* _g_C_P_0, char* _g_C_P_1, char* _g_C_P_2,
             char* _g_H_0, char* _g_H_1, char* _g_H_2, char* _g_K_0, char* _g_K_1, char* _g_K_2, char* _input0 , char* _input1 , char* _input2, char* _input3,
             char* _input4, char* _input5
             ) { 
    //libff::G1<alt_bn128_pp> g_a_0("5");
    libff::bigint<libff::alt_bn128_r_limbs> g_A_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_A_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_A_2;
    libff::bigint<libff::alt_bn128_r_limbs> g_A_P_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_A_P_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_A_P_2;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_2;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_3;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_4;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_5;

    libff::bigint<libff::alt_bn128_r_limbs> g_B_P_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_P_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_P_2;

    libff::bigint<libff::alt_bn128_r_limbs> g_C_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_C_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_C_2;

    libff::bigint<libff::alt_bn128_r_limbs> g_C_P_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_C_P_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_C_P_2;

    libff::bigint<libff::alt_bn128_r_limbs> g_H_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_H_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_H_2;

    libff::bigint<libff::alt_bn128_r_limbs> g_K_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_K_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_K_2;

    typedef bigint<alt_bn128_r_limbs> bigint_r;

    g_A_0 = bigint_r(_g_A_0);
    g_A_1 = bigint_r(_g_A_1);
    g_A_2 = bigint_r(_g_A_2);


    g_A_P_0 = bigint_r(_g_A_P_0);
    g_A_P_1 = bigint_r(_g_A_P_1);
    g_A_P_2 = bigint_r(_g_A_P_2);

    g_B_0 = bigint_r(_g_B_0);
    g_B_1 = bigint_r(_g_B_1);
    g_B_2 = bigint_r(_g_B_2);
    g_B_3 = bigint_r(_g_B_3);
    g_B_4 = bigint_r(_g_B_4);
    g_B_5 = bigint_r(_g_B_5);


    g_B_P_0 = bigint_r(_g_B_P_0);
    g_B_P_1 = bigint_r(_g_B_P_1);
    g_B_P_2 = bigint_r(_g_B_P_2);

    g_C_0 = bigint_r(_g_C_0);
    g_C_1 = bigint_r(_g_C_1);
    g_C_2 = bigint_r(_g_C_2);

    g_C_P_0 = bigint_r(_g_C_P_0);
    g_C_P_1 = bigint_r(_g_C_P_1);
    g_C_P_2 = bigint_r(_g_C_P_2);

    g_H_0 = bigint_r(_g_H_0);
    g_H_1 = bigint_r(_g_H_1);
    g_H_2 = bigint_r(_g_H_2);

    g_K_0 = bigint_r(_g_K_0);
    g_K_1 = bigint_r(_g_K_1);
    g_K_2 = bigint_r(_g_K_2);

    libff::alt_bn128_G1 g1_A(g_A_0, g_A_1, g_A_2);
    libff::alt_bn128_G1 g1_A_P(g_A_P_0, g_A_P_1, g_A_P_2);

    libff::alt_bn128_Fq2 g_B_0_fq2 (g_B_0, g_B_1);
    libff::alt_bn128_Fq2 g_B_1_fq2 (g_B_2, g_B_3);
    libff::alt_bn128_Fq2 g_B_2_fq2 (g_B_4, g_B_5);

    libff::alt_bn128_G2 g2_B( g_B_0_fq2, g_B_1_fq2, g_B_2_fq2);
    libff::alt_bn128_G1 g1_B_P(g_B_P_0, g_B_P_1, g_B_P_2);

    libff::alt_bn128_G1 g1_C(g_C_0, g_C_1, g_C_2);
    libff::alt_bn128_G1 g1_C_P(g_C_P_0, g_C_P_1, g_C_P_2);

    libff::alt_bn128_G1 g1_H(g_H_0, g_H_1, g_H_2);
    libff::alt_bn128_G1 g1_K(g_K_0, g_K_1, g_K_2);

    std::cout <<"g2_B " << g2_B; 
    
    knowledge_commitment<libff::alt_bn128_G1, libff::alt_bn128_G1 > g_A(g1_A, g1_A_P);
    knowledge_commitment<libff::alt_bn128_G2, libff::alt_bn128_G1 > g_B(g2_B, g1_B_P);
    knowledge_commitment<libff::alt_bn128_G1, libff::alt_bn128_G1 > g_C(g1_C, g1_C_P);

    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_proof<libff::alt_bn128_pp>(std::move(g_A), std::move(g_B), std::move(g_C), std::move(g1_H), std::move(g1_K));
  
    r1cs_ppzksnark_primary_input <libff::alt_bn128_pp> primary_input(0, 5);
    libff::bigint<libff::alt_bn128_r_limbs> input0;
    libff::bigint<libff::alt_bn128_r_limbs> input1;
    libff::bigint<libff::alt_bn128_r_limbs> input2;
    libff::bigint<libff::alt_bn128_r_limbs> input3;
    libff::bigint<libff::alt_bn128_r_limbs> input4;
    libff::bigint<libff::alt_bn128_r_limbs> input5;


    input0 = bigint_r(_input0);
    input1 = bigint_r(_input1);
    input2 = bigint_r(_input2);
    input3 = bigint_r(_input3);
    input4 = bigint_r(_input4);
    input4 = bigint_r(_input5);


    primary_input.resize(6);
    primary_input[0] = bigint_r(_input0);
    primary_input[1] = bigint_r(_input1);
    primary_input[2] = bigint_r(_input2);
    primary_input[3] = bigint_r(_input3);
    primary_input[4] = bigint_r(_input4);
    primary_input[5] = bigint_r(_input5);


    r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair;
    keypair.vk = loadFromFile<r1cs_ppzksnark_verification_key<libff::alt_bn128_pp>> (vk);
    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof1 = loadFromFile<r1cs_ppzksnark_proof<libff::alt_bn128_pp>> ("../zksnark_element/proof.raw");
    r1cs_ppzksnark_primary_input <libff::alt_bn128_pp> primary_input1(0, 5);

    std::cout  << "outptu " << std::endl << outputPointG2AffineAsHex(proof.g_B.g) << std::endl << outputPointG2AffineAsHex(proof1.g_B.g) << std::endl;
    bool test = proof == proof1;
    bool test0 = proof.g_A.g == proof1.g_A.g;
    bool test1 = proof.g_A.h == proof1.g_A.h;
    bool test2 = proof.g_B.g == proof1.g_B.g;
    bool test3 = proof.g_A.h == proof1.g_A.h;
    bool test4 = proof.g_C.g == proof1.g_C.g;
    bool test5 = proof.g_C.h == proof1.g_C.h;
    bool test6 = proof.g_H == proof1.g_H;
    bool test7 = proof.g_K == proof1.g_K;
 
    std::cout << " test out " << test << test0 << test1 << test2<< test3<<test4<<test5<<test6<<test7;
    return r1cs_ppzksnark_verifier_strong_IC <libff::alt_bn128_pp> (keypair.vk, primary_input, proof);  

}

char* prove(bool in_signal[256], char* pk, bool isInt)
{ 
    libff::alt_bn128_pp::init_public_params();
    libff::bit_vector signal(0,256);

    signal.resize(256);

    for( int j = 0; j < 256; j ++ )
    {
        signal[j] = in_signal[j];
    }

    libff::alt_bn128_pp::init_public_params();
    Miximus<FieldT, sha256_ethereum> c;

    auto out = c.prove(signal, pk, isInt);

    return(out); 
}

