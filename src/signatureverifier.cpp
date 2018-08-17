/*
 *  This file is part of WinSparkle (https://winsparkle.org)
 *
 *  Copyright (C) 2017-2018 Ihor Dutchak
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction, including without limitation
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *  and/or sell copies of the Software, and to permit persons to whom the
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 *
 */

#include "signatureverifier.h"

#include "error.h"
#include "settings.h"
#include "utils.h"

#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <stdexcept>

#include <windows.h>
#include <wincrypt.h>

#ifdef _MSC_VER
#pragma comment(lib, "crypt32.lib")
#endif

namespace winsparkle
{

namespace
{

class CFile
{
    FILE *f;
    CFile(const CFile &);
    CFile &operator=(const CFile &);
public:
    CFile(FILE *file): f(file) {}

    operator FILE*()
    {
        return f;
    }

    ~CFile()
    {
        if (f)
            fclose(f);
    }
};

class WinCryptRSAContext
{
    HCRYPTPROV handle;

    WinCryptRSAContext(const WinCryptRSAContext &);
    WinCryptRSAContext &operator=(const WinCryptRSAContext &);
public:
    WinCryptRSAContext()
    {
        if (!CryptAcquireContextW(&handle, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            throw Win32Exception("Failed to create crypto context");
    }

    ~WinCryptRSAContext()
    {
        if (!CryptReleaseContext(handle, 0))
            LogError("Failed to release crypto context");
    }

    operator HCRYPTPROV()
    {
        return handle;
    }
};

// XXX: Duo Modified
class WinCryptSHAHash
{
    WinCryptSHAHash(const WinCryptSHAHash&);
    WinCryptSHAHash& operator=(const WinCryptSHAHash &);
    HCRYPTHASH handle;

    DWORD shaLength;

public:
	WinCryptSHAHash(WinCryptRSAContext& context, int algorithm)
    {
        if (!CryptCreateHash(HCRYPTPROV(context), algorithm, 0, 0, &handle))
            throw Win32Exception("Failed to create crypto hash");
        
        switch (algorithm)
        {
        case CALG_SHA_512:
            shaLength = SHA512_DIGEST_LENGTH;
            break;
        case CALG_SHA_384:
            shaLength = SHA384_DIGEST_LENGTH;
            break;
        case CALG_SHA_256:
            shaLength = SHA256_DIGEST_LENGTH;
            break;
        case CALG_SHA1:
            shaLength = SHA_DIGEST_LENGTH;
            break;
        default:
            shaLength = 0;
        }
        if (shaLength == 0)
        {
            throw Win32Exception("Invalid Hash Algorithm, can't create digest length");
        }
    }

    ~WinCryptSHAHash()
    {
        if (handle)
        {
            if (!CryptDestroyHash(handle))
            {
                LogError("Failed to destroy crypto hash");
            }
        }
    }

    DWORD GetShaLength() const { return shaLength; }

    void hashData(const void *buffer, size_t buffer_len)
    {
        if (!CryptHashData(handle, (CONST BYTE  *)buffer, buffer_len, 0))
            throw Win32Exception("Failed to hash data");
    }

    void hashFile(const std::wstring &filename)
    {
        CFile f (_wfopen(filename.c_str(), L"rb"));
        if (!f)
            throw std::runtime_error(WideToAnsi(L"Failed to open file " + filename));

        const int BUF_SIZE = 8192;
        unsigned char buf[BUF_SIZE];

        while (size_t read_bytes = fread(buf, 1, BUF_SIZE, f))
        {
            hashData(buf, read_bytes);
        }

        if (ferror(f))
            throw std::runtime_error(WideToAnsi(L"Failed to read file " + filename));
    }

    void shaVal(unsigned char *sha)
    {
        if (!CryptGetHashParam(handle, HP_HASHVAL, sha, &shaLength, 0))
            throw Win32Exception("Failed to get SHA val");
    }
};
// XXX: End Duo Modified

/**
    Light-weight dynamic loader of OpenSSL library.
    Loads only minimum required symbols, just enough to verify DSA SHA512 signature of the file.
 */
class TinySSL
{
    TinySSL() {}
public:
    static TinySSL &inst()
    {
        static TinySSL instance;
        return instance;
    }

    ~TinySSL()
    {
    }

    void HashFile(const std::wstring &filename, const unsigned int algorithm, unsigned char* sha, const DWORD& hashLength)
    {
        WinCryptRSAContext ctx;
        // SHA of file
        {
            WinCryptSHAHash hash(ctx, algorithm);
            hash.hashFile(filename);
            hash.shaVal(sha);
        }
        // SHA of SHA of file
        {
            WinCryptSHAHash hash(ctx, algorithm);
            hash.hashData(sha, hashLength);
            hash.shaVal(sha);
        }
    }

    void VerifySignature(unsigned char* sha, const DWORD& hashLength, const std::string &signature)
    {
        ECDSAPub pubKey(Settings::GetDSAPubKeyPem());

        const int code = ECDSA_verify(0, sha, hashLength, (const unsigned char*)signature.c_str(), signature.size(), pubKey);

        if (code == -1) // OpenSSL error
            throw BadSignatureException(ERR_error_string(ERR_get_error(), nullptr));

        if (code != 1)
            throw BadSignatureException();
    }

	// XXX: Duo Modified
    void VerifyDSASHASignature(const std::wstring &filename, const std::string &signature)
    {
        unsigned int algorithm = Settings::GetSHAAlgorithm();
        switch (algorithm)
        {
        case CALG_SHA_512:
            {
                const DWORD length = SHA512_DIGEST_LENGTH;
                unsigned char sha[length];
                HashFile(filename, algorithm, sha, length);
                VerifySignature(sha, length, signature);
            }
            break;
        case CALG_SHA_384:
            {
                const DWORD length = SHA384_DIGEST_LENGTH;
                unsigned char sha[length];
                HashFile(filename, algorithm, sha, length);
                VerifySignature(sha, length, signature);
            }
            break;
        case CALG_SHA_256:
            {
                const DWORD length = SHA256_DIGEST_LENGTH;
                unsigned char sha[length];
                HashFile(filename, algorithm, sha, length);
                VerifySignature(sha, length, signature);
            }
            break;
        default:
            {
                algorithm = CALG_SHA1;
                const DWORD length = SHA_DIGEST_LENGTH;
                unsigned char sha[length];
                HashFile(filename, algorithm, sha, length);
                VerifySignature(sha, length, signature);
            }
            break;
        }
    }
	// XXX: End Duo Modified

private:
    class BIOWrap
    {
        BIO* bio = NULL;

        BIOWrap(const BIOWrap &);
        BIOWrap &operator=(const BIOWrap &);

    public:
        BIOWrap(const std::string &mem_buf)
        {
            bio = BIO_new_mem_buf(mem_buf.c_str(), int(mem_buf.size()));
            if (!bio)
                throw std::invalid_argument("Cannot set PEM key mem buffer");
        }

        operator BIO*()
        {
            return bio;
        }

        ~BIOWrap()
        {
            BIO_free(bio);
        }

    }; // BIOWrap

public:
    class DSAPub
    {
        DSA *dsa = NULL;

        DSAPub(const DSAPub &);
        DSAPub &operator=(const DSAPub &);

    public:
        DSAPub(const std::string &pem_key)
        {
            BIOWrap bio(pem_key);
            if (!PEM_read_bio_DSA_PUBKEY(bio, &dsa, NULL, NULL))
            {
                throw std::invalid_argument("Cannot read DSA public key from PEM");
            }
        }

        operator DSA*()
        {
            return dsa;
        }

        ~DSAPub()
        {
            if (dsa)
                DSA_free(dsa);
        }

    }; // DSAWrap

    class ECDSAPub
    {
        EC_KEY *ecdsa = NULL;

        ECDSAPub(const ECDSAPub &);
        ECDSAPub &operator=(const ECDSAPub &);

    public:
        ECDSAPub(const std::string &pem_key)
        {
            BIOWrap bio(pem_key);
            if (!PEM_read_bio_EC_PUBKEY(bio, &ecdsa, NULL, NULL))
            {
                throw std::invalid_argument("Cannot read ECDSA public key from PEM");
            }
        }

        operator EC_KEY*()
        {
            return ecdsa;
        }

        ~ECDSAPub()
        {
            if (ecdsa)
                EC_KEY_free(ecdsa);
        }

    };

}; // TinySSL

std::string Base64ToBin(const std::string &base64)
{
    DWORD nDestinationSize = 0;
    std::string bin;

    bool ok = false;

    if (CryptStringToBinaryA(&base64[0], base64.size(), CRYPT_STRING_BASE64, NULL, &nDestinationSize, NULL, NULL))
    {
        bin.resize(nDestinationSize);
        if (CryptStringToBinaryA(&base64[0], base64.size(), CRYPT_STRING_BASE64, (BYTE *)&bin[0], &nDestinationSize, NULL, NULL))
        {
            ok = true;
        }
    }

    if (!ok)
        throw std::runtime_error("Failed to decode base64 string");

    return bin;
}

} // anonynous

void SignatureVerifier::VerifyDSAPubKeyPem(const std::string &pem)
{
    // DSAPub::DSAPub() throw if not valid
    TinySSL::ECDSAPub dsa_pub(pem);
    (void)dsa_pub;
}

void SignatureVerifier::VerifyDSASHASignatureValid(const std::wstring &filename, const std::string &signature_base64)
{
    try
    {
        if (signature_base64.size() == 0)
            throw BadSignatureException("Missing DSA signature!");

        TinySSL::inst().VerifyDSASHASignature(filename, Base64ToBin(signature_base64));
    }
    catch (BadSignatureException&)
    {
        throw;
    }
    catch (const std::exception &e)
    {
        throw BadSignatureException(e.what());
    }
    catch (...)
    {
        throw BadSignatureException();
    }
}

} // namespace winsparkle
