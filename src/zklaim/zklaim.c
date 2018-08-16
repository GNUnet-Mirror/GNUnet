/*
 * This file is part of zklaim.
 * zklaim is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * zklaim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with zklaim. If not, see https://www.gnu.org/licenses/.
 */


/**
 * Test File for zklaim c implementation
 */

#include <zklaim/zklaim.h>
#include <zklaim/zklaim_ecc.h>
#include <zklaim/zklaim_hash.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gcrypt.h>

// to boost up valgrind
int worker() {
    gcry_sexp_t priv, pub;
    zklaim_gen_pk(&priv);
    zklaim_get_pub(priv, &pub);
    unsigned char *pubbuf;
    size_t publen;
    zklaim_pub2buf(pub, &pubbuf, &publen);

    printf("===========================================================================\n");
    printf("===========================================================================\n");
    printf("============================== ISSUER =====================================\n");
    printf("===========================================================================\n");
    printf("===========================================================================\n");
    //zklaim_ctx* ctx = zklaim_context_init();
    //zklaim_proving_key* pk = zklaim_proving_key_get(ctx);
    /*
     * - 1 -
     * initialize data structures
     */
    printf("[ISSUER] initializing context\n");
    zklaim_ctx *ctx = zklaim_context_new();

    if (sizeof(ctx->pub_key) != publen) {
        printf("size mismatch!");
        return 1;
    }

    // TODO: there should be a zklaim method for this
    memcpy(ctx->pub_key, pubbuf, sizeof(ctx->pub_key));
    free(pubbuf);

    //print_sexp(pub);

    /*
     * - 2 -
     * setup the first payload
     */
    printf("[ISSUER] Setting up payloads..\n");
    zklaim_payload pl, pl2;
    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data0_ref = 18;
    pl.data0_op = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data1_ref = 1;
    pl.data1_op = zklaim_eq;
    pl.data2_ref = 2;
    pl.data2_op = zklaim_eq;
    pl.data3_ref = 3;
    pl.data3_op = zklaim_eq;
    pl.data4_ref = 600;
    pl.data4_op = zklaim_less;
    pl.priv = 0;

    memset(&pl2, 0, sizeof(zklaim_payload));
    pl2.data0_ref = 0;
    pl2.data0_op = zklaim_noop;
    pl2.data1_ref = 0;
    pl2.data1_op = zklaim_noop;
    pl2.data2_ref = 0;
    pl2.data2_op = zklaim_noop;
    pl2.data3_ref = 0;
    pl2.data3_op = zklaim_noop;
    pl2.data4_ref = 9223372036854775807;
    pl2.data4_op = zklaim_less_or_eq;
    pl2.priv = 0;

    // fill in the values
    zklaim_set_attr(&pl, 23, 0);
    zklaim_set_attr(&pl, 1, 1);
    zklaim_set_attr(&pl, 2, 2);
    zklaim_set_attr(&pl, 3, 3);
    zklaim_set_attr(&pl, 599, 4);

    zklaim_set_attr(&pl2, 0, 0);
    zklaim_set_attr(&pl2, 0, 1);
    zklaim_set_attr(&pl2, 0, 2);
    zklaim_set_attr(&pl2, 0, 3);
    zklaim_set_attr(&pl2, 9223372036854775807, 4);

    /*
     * - 3 -
     * add payload to context
     */
    printf("[ISSUER] adding payloads to context\n");
    zklaim_add_pl(ctx, pl);
    /* zklaim_add_pl(ctx, pl); */
    //zklaim_add_pl(ctx, pl2);
    zklaim_hash_ctx(ctx);

    printf("[ISSUER] performing trusted setup in order to generate keys\n");
    printf("-> trusted setup result: %s\n", (zklaim_trusted_setup(ctx) ? "failed" : "passed"));

    //unsigned char* buf;
    //size_t vksize = zklaim_verification_key_serialize(ctx, &buf);
    //printf("serialized vk size: %zuB\n", vksize);

    // write key to disk
    //FILE* f = fopen("/tmp/vk1", "w");
    //fwrite(buf, vksize, 1, f);
    //fclose(f);

    //zklaim_verification_key_deserialize(ctx2, buf, vksize);

    //free(buf);

    //size_t pksize = zklaim_proving_key_serialize(ctx, &buf);
    //printf("serialized pk size: %.2fMB\n", ((float) pksize)/1000/1000);

    //zklaim_proving_key_deserialize(ctx, buf, pksize);

    //zklaim_print(ctx);

    //zklaim_ctx_sign(ctx, priv);


    printf("-> signing context: %s\n", zklaim_ctx_sign(ctx, priv) ? "failed" : "passed");

    unsigned char* ctx_issuer;

    printf("\n[ISSUER] serializing context\n");
    size_t len = zklaim_ctx_serialize(ctx, &ctx_issuer);

    /*
     * - 4 -
     * generate proof
     */

    //printf("\n-> signing context: %s\n", zklaim_ctx_sign(ctx, priv) ? "failed" : "passed");

    //unsigned char* proof;
    //size_t proof_size = zklaim_proof_serialize(ctx, &proof);
    //printf("serialized proof size: %zuB\n", proof_size);

    //zklaim_proof* zkproof_imported;

    //zklaim_proof_deserialize(ctx, proof, proof_size);

    printf("===========================================================================\n");
    printf("===========================================================================\n");
    printf("============================== PROVER =====================================\n");
    printf("===========================================================================\n");
    printf("===========================================================================\n");


    zklaim_ctx* ctx_prover = zklaim_context_new();
    printf("\n[PROVER] deserializing context\n");
    printf("-> deserialisation status: %s\n\n", zklaim_ctx_deserialize(ctx_prover, ctx_issuer, len) ? "failed" : "passed");

    zklaim_print(ctx_prover);

    ctx_prover->pk = ctx->pk;

    int res = zklaim_ctx_verify(ctx_prover);
    printf("[PROVER] verification result: %d %s\n", res, (res ? "failed" : "passed"));
    printf("                              ^--- failure with code 3 (ZKLAIM_INVALID_PROOF) is ok for the prover, as signature passes, but (non-existing) proof fails\n\n");

    printf("[PROVER] resetting operations and reference values to create taylored proof\n");
    printf("[PROVER] generating proof\n");

    ctx_prover->pk = (unsigned char*) calloc(1, ctx->pk_size);
    ctx_prover->pk_size = ctx->pk_size;
    memcpy(ctx_prover->pk, ctx->pk, ctx_prover->pk_size);

    // set custom prover reference values here:
    ctx_prover->pl_ctx_head->pl.data0_ref = 20;
    /* ctx_prover->pl_ctx_head->next->pl.data0_ref = 30; */
    /* ctx_prover->pl_ctx_head->next->pl.data0_op = zklaim_less_or_eq; */
    //ctx_prover->pl_ctx_head->pl.data0_op = zklaim_less;
    ctx_prover->pl_ctx_head->pl.data4_ref = 0;
    ctx_prover->pl_ctx_head->pl.data4_op = zklaim_noop;

    ctx_prover->pl_ctx_head->pl.data1_ref = 0;
    ctx_prover->pl_ctx_head->pl.data1_op = zklaim_noop;

    ctx_prover->pl_ctx_head->pl.data2_ref = 0;
    ctx_prover->pl_ctx_head->pl.data2_op = zklaim_noop;

    ctx_prover->pl_ctx_head->pl.data3_ref = 0;
    ctx_prover->pl_ctx_head->pl.data3_op = zklaim_noop;

    zklaim_print(ctx_prover);

    printf("-> proof generation status: %s\n\n", (zklaim_proof_generate(ctx_prover) ? "failed" : "passed"));


    printf("[PROVER] blinding attributes\n");
    zklaim_clear_pres(ctx_prover);


    printf("[PROVER] serializing context\n\n");

    unsigned char *ctx_prover_buf;
    len = zklaim_ctx_serialize(ctx_prover, &ctx_prover_buf);

    /*
     * - 5 -
     * verify proof
     */
    printf("===========================================================================\n");
    printf("===========================================================================\n");
    printf("============================= VERIFIER ====================================\n");
    printf("===========================================================================\n");
    printf("===========================================================================\n");

    zklaim_ctx* ctx_verifier = zklaim_context_new();
    printf("\n[VERIFIER] deserializing context\n");
    printf("-> deserialisation status: %s\n\n", zklaim_ctx_deserialize(ctx_verifier, ctx_prover_buf, len) ? "failed" : "passed");
    printf("[VERIFIER] verifying proof and context\n");
    res = zklaim_ctx_verify(ctx_verifier);
    printf("verification result: %d %s\n\n", res, (res ? "failed" : "passed"));

    zklaim_print(ctx_verifier);

    free(ctx_prover_buf);
    free(ctx_issuer);
    zklaim_ctx_free(ctx);
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    zklaim_ctx_free(ctx_prover);
    zklaim_ctx_free(ctx_verifier);

    return ZKLAIM_OK;
}

int main() {
    return worker();
}
