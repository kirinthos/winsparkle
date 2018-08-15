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
// created base class to add support for sha512
class WinCryptSHAHash
{
    WinCryptSHAHash(const WinCryptSHAHash&);
    WinCryptSHAHash& operator=(const WinCryptSHAHash &);
protected:
    HCRYPTHASH handle;

	WinCryptSHAHash(WinCryptRSAContext& context, int algorithm)
    {
        if (!CryptCreateHash(HCRYPTPROV(context), algorithm, 0, 0, &handle))
            throw Win32Exception("Failed to create crypto hash");
    }

public:
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
};

class WinCryptSHA1Hash : public WinCryptSHAHash
{
public:
	WinCryptSHA1Hash(WinCryptRSAContext &context)
		: WinCryptSHAHash(context, CALG_SHA1)
	{}

    void shaVal(unsigned char(&sha)[SHA_DIGEST_LENGTH])
    {
        DWORD hash_len = SHA_DIGEST_LENGTH;
        if (!CryptGetHashParam(handle, HP_HASHVAL, sha, &hash_len, 0))
            throw Win32Exception("Failed to get SHA val");
    }
};

class WinCryptSHA512Hash : public WinCryptSHAHash
{
public:
	WinCryptSHA512Hash(WinCryptRSAContext &context)
		: WinCryptSHAHash(context, CALG_SHA_512)
	{}

    void shaVal(unsigned char(&sha)[SHA512_DIGEST_LENGTH])
    {
        DWORD hash_len = SHA512_DIGEST_LENGTH;
        if (!CryptGetHashParam(handle, HP_HASHVAL, sha, &hash_len, 0))
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

	// XXX: Duo Modified
    void VerifyDSASHA512Signature(const std::wstring &filename, const std::string &signature)
    {
        unsigned char sha[SHA512_DIGEST_LENGTH];

        {
            WinCryptRSAContext ctx;
            // SHA of file
            {
                WinCryptSHA512Hash hash(ctx);
                hash.hashFile(filename);
                hash.shaVal(sha);
            }
            // SHA of SHA of file
            {
                WinCryptSHA512Hash hash(ctx);
                hash.hashData(sha, ARRAYSIZE(sha));
                hash.shaVal(sha);
            }
        }

        DSAPub pubKey(Settings::GetDSAPubKeyPem());

        const int code = DSA_verify(0, sha, ARRAYSIZE(sha), (const unsigned char*)signature.c_str(), signature.size(), pubKey);

        if (code == -1) // OpenSSL error
            throw BadSignatureException(ERR_error_string(ERR_get_error(), nullptr));

        if (code != 1)
            throw BadSignatureException();
    }

    void VerifyDSASHA1Signature(const std::wstring &filename, const std::string &signature)
    {
        unsigned char sha[SHA_DIGEST_LENGTH];

        {
            WinCryptRSAContext ctx;
            // SHA of file
            {
                WinCryptSHA1Hash hash(ctx);
                hash.hashFile(filename);
                hash.shaVal(sha);
            }
            // SHA of SHA of file
            {
                WinCryptSHA1Hash hash(ctx);
                hash.hashData(sha, ARRAYSIZE(sha));
                hash.shaVal(sha);
            }
        }

        DSAPub pubKey(Settings::GetDSAPubKeyPem());

        const int code = DSA_verify(0, sha, ARRAYSIZE(sha), (const unsigned char*)signature.c_str(), signature.size(), pubKey);

        if (code == -1) // OpenSSL error
            throw BadSignatureException(ERR_error_string(ERR_get_error(), nullptr));

        if (code != 1)
            throw BadSignatureException();
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
    TinySSL::DSAPub dsa_pub(pem);
    (void)dsa_pub;
}

void SignatureVerifier::VerifyDSASHASignatureValid(const std::wstring &filename, const std::string &signature_base64)
{
    try
    {
        if (signature_base64.size() == 0)
            throw BadSignatureException("Missing DSA signature!");

		// XXX: Duo Modified
		if (Settings::GetSHAAlgorithm() == CALG_SHA_512)
		{
			TinySSL::inst().VerifyDSASHA512Signature(filename, Base64ToBin(signature_base64));
		}
		else
		{
			throw BadSignatureException("We want to use SHA512!");
			TinySSL::inst().VerifyDSASHA1Signature(filename, Base64ToBin(signature_base64));
		}
		// XXX: End Duo Modified
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
