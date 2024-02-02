#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>


#include "rpcool.h"

static struct crypto_shash *alg = NULL;


struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);

	sdesc->shash.tfm = alg;
	return sdesc;
}

static int calc_hash(struct crypto_shash *alg, const unsigned char *data, unsigned int datalen,
		     unsigned char *digest)
{
	struct sdesc *sdesc;
	int ret;

	sdesc = init_sdesc(alg);
	if (IS_ERR(sdesc)) {
		pr_info("can't alloc sdesc\n");
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
	kfree(sdesc);
	return ret;
}

// Function to print hash
void print_hash(const unsigned char *hash)
{
	pr_info("Hash: ");
	for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
		pr_cont("%02x", hash[i]);
	}
	pr_cont("\n");
}

int init_hash_algorithm(void)
{
	char *hash_alg_name = "sha256";

    if (alg != NULL) {
        pr_info("[rpcool] alg is already initilaized\n");
        return 0;
    }

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
	if (IS_ERR(alg)) {
        pr_err("[rpcool] can't alloc alg %s\n", hash_alg_name);
		return -1;
	}
    pr_info("[rpcool] alg %s is initialized\n", hash_alg_name);
    //crypto_free_shash(alg);
    return 0;
}


static unsigned char * concat_key_index_nonce(const unsigned char *key, size_t key_size, uint64_t index, uint64_t nonce) {
    size_t total_size = key_size + sizeof(index) + sizeof(nonce);
    unsigned char *new_data = kmalloc(total_size, GFP_KERNEL);

    if (!new_data) {
        pr_err("[rpcool] can't alloc new_data\n");
        return NULL;
    }

    memcpy(new_data, key, key_size);
    memcpy(new_data + key_size, &index, sizeof(index));
    memcpy(new_data + key_size + sizeof(index), &nonce, sizeof(nonce));

    return new_data;
}




unsigned char * calc_hash_now(unsigned char *key, size_t key_size, uint64_t index, uint64_t nonce) {
    int ret;
    unsigned char *digest;
    unsigned char *modified_data;
    size_t total_size = key_size + sizeof(index) + sizeof(nonce);

    modified_data = concat_key_index_nonce(key, key_size, index, nonce);
    if (!modified_data) {
        pr_err("[rpcool] can't concat key, index, and nonce\n");
        return NULL;
    }

    digest = kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
    if (!digest) {
        pr_err("[rpcool] can't alloc digest\n");
        kfree(modified_data);
        return NULL;
    }

    ret = calc_hash(alg, modified_data, total_size, digest);
    kfree(modified_data);

    if (ret != 0) {
        pr_info("[rpcool] Hash calculation failed\n");
        kfree(digest);
        return NULL;
    }

    pr_info("Hash calculated successfully\n");
    return digest;
}


bool compare_signatures(const unsigned char *digest, 
                                   const unsigned char *signature) {
	const int digest_size = SHA256_DIGEST_SIZE;

    if (!digest || !signature) {
        pr_err("Invalid arguments to compare_digest_with_signature\n");
        return false;
    }

    // Using crypto_memneq for time-constant comparison
    return crypto_memneq(digest, signature, digest_size) == 0;
}


int validate_signature(const unsigned char __user *user_signature, const unsigned char *key, size_t key_size, uint64_t index, uint64_t nonce) {
    unsigned char signature_buffer[SHA256_DIGEST_SIZE];
    unsigned char *digest;
    int ret;

    if (copy_from_user(signature_buffer, user_signature, SHA256_DIGEST_SIZE) != 0) {
        printk("[rpcool] validate_signature: could not copy signature from userspace\n");
        return -EFAULT;
    }
    printk("[rpcool] validate_signature: user provided signature is: \n");
    print_hash(signature_buffer);

    digest = calc_hash_now(key, key_size, index, nonce);
    if (digest == NULL) {
        printk("[rpcool] validate_signature: could not calculate hash\n");
        return -EINVAL;
    }

    printk("[rpcool] validate_signature: calculating signiture for index = %llu, nonce = %llu\n", index, nonce);
    printk("[rpcool] validate_signature: calculated signature (digest) is: \n");
    print_hash(digest);

    if (!compare_signatures(digest, signature_buffer)) {
        printk("[rpcool] validate_signature: signatures do not match\n");
        kfree(digest);
        return -EACCES;
    }

    printk("[rpcool] validate_signature: signatures is valid\n");
    kfree(digest);
    return 0;
}