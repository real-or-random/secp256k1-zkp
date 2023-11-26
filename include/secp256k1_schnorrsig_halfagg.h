#ifndef SECP256K1_SCHNORRSIG_HALFAGG_H
#define SECP256K1_SCHNORRSIG_HALFAGG_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif


/** Incrementally (Half-)Aggregate a sequence of Schnorr
 *  signatures to an existing half-aggregate signature.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:           ctx: a secp256k1 context object.
 *  In/Out:      aggsig: pointer to the serialized aggregate signature
 *                       that is input. Will be overwritten by the new
 *                       serialized aggregate signature.
 *          aggsig_size: size of the memory allocated in aggsig.
 *                       Should be large enough to hold the new
 *                       serialized aggregate signature.
 *                       I.e., should be a multiple of 32 and should
 *                       satisfy aggsig_size >= 32*(n_before+n_new+1)
 *  In:     all_pubkeys: Array of x-only public keys, including both
 *                       the ones for the already aggregated signature
 *                       and the ones for the signatures that should be added.
 *                       Assumed to contain n = n_before + n_new many public keys.
 *           all_msgs32: Array of 32-byte messages, including both
 *                       the ones for the already aggregated signature
 *                       and the ones for the signatures that should be added.
 *                       Assumed to contain n = n_before + n_new many messages.
 *           new_sigs64: Array of 64-byte signatures, containing the new
 *                       signatures that should be added.
 *                       Assumed to contain n_new many signatures.
 *             n_before: Number of signatures that are already "contained"
 *                       in the aggregate signature.
 *                n_new: Number of signatures that should now be added
 *                       to the aggregate signature.
 */
SECP256K1_API int secp256k1_schnorrsig_inc_aggregate(
    const secp256k1_context *ctx,
    unsigned char *aggsig,
    size_t *aggsig_size,
    const secp256k1_xonly_pubkey* all_pubkeys,
    const unsigned char *all_msgs32,
    const unsigned char *new_sigs64,
    size_t n_before,
    size_t n_new
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** (Half-)Aggregate a sequence of Schnorr signatures.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:           ctx: a secp256k1 context object.
 *  Out:         aggsig: pointer to an array of aggsig_size many bytes to
 *                       store the serialized aggregate signature.
 *  In/Out: aggsig_size: size of the aggsig array that is passed;
 *                       will be overwritten to be the exact size of aggsig.
 *  In:         pubkeys: Array of x-only public keys.
 *                       Assumed to contain n many public keys.
 *               msgs32: Array of 32-byte messages.
 *                       Assumed to contain n many messages.
 *               sigs64: Array of 64-byte signatures.
 *                       Assumed to contain n many signatures.
 *                    n: number of signatures to be aggregated.
 */
SECP256K1_API int secp256k1_schnorrsig_aggregate(
    const secp256k1_context *ctx,
    unsigned char *aggsig,
    size_t *aggsig_size,
    const secp256k1_xonly_pubkey *pubkeys,
    const unsigned char *msgs32,
    const unsigned char *sigs64,
    size_t n
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Verify a (Half-)aggregate Schnorr signature.
 *
 *  Returns:          1: correct signature.
 *                    0: incorrect signature.
 *  Args:           ctx: a secp256k1 context object.
 *  In:         pubkeys: Array of x-only public keys.
 *                       Assumed to contain n many public keys.
 *               msgs32: Array of 32-byte messages.
 *                       Assumed to contain n many messages.
 *                    n: number of signatures to that have been aggregated.
 *               aggsig: Pointer to an array of aggsig_size many bytes
 *                       containing the serialized aggregate
 *                       signature to be verified.
 *          aggsig_size: Size of the aggregate signature.
 *                       Should be aggsig_size = 32*(n+1)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_aggverify(
    const secp256k1_context *ctx,
    const secp256k1_xonly_pubkey *pubkeys,
    const unsigned char *msgs32,
    size_t n,
    const unsigned char *aggsig,
    size_t aggsig_size
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SCHNORRSIG_HALFAGG_H */
