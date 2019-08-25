// MakeCredential.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <WTypesbase.h>
#include <webauthn.h>
#include <vector>
using namespace std;

constexpr unsigned int shash(const wchar_t* s, int off = 0) {
	return !s[off] ? 5381 : (shash(s, off + 1) * 33) ^ s[off];
}

BOOL WriteCredentialData(PCWCHAR fileName, PBYTE pb, DWORD pbLen)
{
	HANDLE hFile = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwWritten = 0;
	BOOL success = WriteFile(hFile, pb, pbLen, &dwWritten, NULL);
	success = CloseHandle(hFile);
	return success == (dwWritten == pbLen);
}

void PrintHelp(wchar_t* exe)
{
	wprintf(L"Usage:\n\n");
	wprintf(L"%s [operation] [options]\n\n", exe);
	wprintf(L"Operation:\n");
	wprintf(L"\tattest (MakeCredential) OR assert (GetAssertion)\n\n");
	wprintf(L"Common Options:\n");
	wprintf(L"-rpid\t\tRelying party identifier.\n\t\tDefaults to login.windows.net if not specified. See https://www.w3.org/TR/webauthn/#relying-party-identifier.\n");
	wprintf(L"-rpname\t\tRelying party display name.  Defaults to \"Login dot Windows dot Net\".\n");
	wprintf(L"-rpicon\t\tOptional, URL for relying party, like https://www.w3.org/favicon.ico.\n");
	wprintf(L"-userid\t\tOptional, user identifier.\n");
	wprintf(L"-alg\t\tCOSE algorithm to be used for signature.\n\t\tOne or more of -7, -35, -36, -37, -38, -39, -257, -258, -259.  See https://www.iana.org/assignments/cose/cose.xhtml#algorithms.\n");
	wprintf(L"-challenge\tBase64url encoded byte array for clientDataJSON.\n\t\tDefaults to VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUgbGF6eSBkb2cu.  See https://www.w3.org/TR/webauthn/#dictdef-collectedclientdata.\n");
	wprintf(L"-hashalg\tHash algorithm to be used to sign clientDataJSON.  One of \"SHA-256\", \"SHA-384\", \"SHA-512\".  Defaults to \"SHA-256\"\n");
	wprintf(L"-origin\t\tOrigin parameter for clientDataJSON.  See https://www.w3.org/TR/webauthn/#dictdef-collectedclientdata.\n");
	wprintf(L"-timeout\tNumber of milliseconds to allow the authenticator operation to complete.  Defaults to 60000.\n");
	wprintf(L"-attach\t\tOptional authenticator attachment value for authenticator selection.\n\t\t0 = any, 1 = platform, 2 = cross-platform. See https://www.w3.org/TR/webauthn/#attachment.\n");
	wprintf(L"-resident\tOptional require resident credential for authenticator selection.\n\t\tFalse if not present.  See https://www.w3.org/TR/webauthn/#client-side-resident-public-key-credential-source.\n");
	wprintf(L"-verify\t\tOptional require user verification.\n\t\t0 = any, 1 = required, 2 = preferred, 3 = discouraged.  Defaults to any.  See https://www.w3.org/TR/webauthn/#enumdef-userverificationrequirement.\n");
	wprintf(L"-convey\t\tOptional attestation conveyance preference.\n\t\t0 = any, 1 = none, 2 = indirect, 3 = direct.  See https://www.w3.org/TR/webauthn/#attestation-convey.\n");
	wprintf(L"-hmacsecret\tOptional request hmac-secret extension.\n\t\tSee https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-client-to-authenticator-protocol-v2.0-rd-20180702.html#sctn-hmac-secret-extension.\n");
	wprintf(L"-exclude\tOptional, one or more transports to specify to the authenticator not to use.\n\t\t1 = USB, 2 = NFC, 4 = BLE, 16 = internal.  Defaults to allow any.  See https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport.\n");
	wprintf(L"-username\tOptional, user short name, like \"aseigler\". Used only in attest operation.\n");
	wprintf(L"-usericon\tOptional, user icon, like an avatar or thumbnail photo. Used only in attest operation.\n");
	wprintf(L"-userdispname\tOptional, user display name, like \"Alex Seigler\". Used only in attest operation.\n");
}

int wmain(int argc, WCHAR* argv[])
{
	if (argc < 2) {
		PrintHelp(argv[0]);
		return 0;
	}
	wchar_t* operation = argv[1];

	WEBAUTHN_RP_ENTITY_INFORMATION rPInformation = {
		WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, // Structure version
		L"login.windows.net",
		L"Login dot Windows dot Net", 
		nullptr, 
	}; 

	WEBAUTHN_USER_ENTITY_INFORMATION userInformation = {
		WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION, // Structure version
		0, 
		nullptr, 
		nullptr,
		nullptr, 
		nullptr, 
	};

	vector<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> coseParams;
	vector<WEBAUTHN_CREDENTIAL_EX> excludedCreds;
	WEBAUTHN_CREDENTIAL_LIST excludedCredsList = { 0 };
	WEBAUTHN_CREDENTIAL_EX* pExcludeCredentials = nullptr;
	vector<WEBAUTHN_CREDENTIAL_EX*> excludedCredsPtrs;
	
	WEBAUTHN_CLIENT_DATA webAuthNClientData = {
		WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,  // Structure version
		0, 
		nullptr, 
		WEBAUTHN_HASH_ALGORITHM_SHA_256,
	};

	WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS webAuthNMakeCredentialOptions = {
		WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
		60000,
		{0, NULL},
		{0, NULL},
		WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
		FALSE,
		WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY,
		WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY,
		0,     // Flags
		NULL,  // CancellationId
		NULL,
	};

	WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS webAuthNAssertionOptions = {
		WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
		60000,
		{0, NULL},
		{0, NULL},
		WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
		FALSE,
		0,  // dwFlags
		NULL,
		NULL,
		nullptr,  // pCancellationId
		NULL,
	};

	vector<WEBAUTHN_EXTENSION> extensions;
	const wchar_t* challenge = L"VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUgbGF6eSBkb2cu";
	const wchar_t* hashAlg = L"SHA-256";
	const wchar_t* origin = L"login.windows.net";
	BOOL fHmacSecret = FALSE;

	for (int i = 2; i < argc; ++i)
	{

		switch (shash(argv[i]))
		{
			case shash(L"-rpid"):
				rPInformation.pwszId = argv[i + 1];
				++i;
				break;

			case shash(L"-rpname"):
				rPInformation.pwszName = argv[i + 1];
				++i;
				break;

			case shash(L"-rpicon"):
				rPInformation.pwszIcon = argv[i + 1];
				++i;
				break;

			case shash(L"-userid"):
				userInformation.pbId = (BYTE*) (argv[i + 1]);
				userInformation.cbId = wcslen(argv[i + 1]);
				++i;
				break;

			case shash(L"-username"):
				userInformation.pwszName = argv[i + 1];
				++i;
				break;

			case shash(L"-usericon"):
				userInformation.pwszIcon = argv[i + 1];
				++i;
				break;

			case shash(L"-userdispname"):
				userInformation.pwszDisplayName = argv[i + 1];
				++i;
				break;

			case shash(L"-alg"): {
					WEBAUTHN_COSE_CREDENTIAL_PARAMETER coseParam = {
						WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, // Structure version
						WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, // "public-key" string constant
						wcstol(argv[i + 1], NULL, 0),
					};
					++i;
					coseParams.push_back(coseParam);
				}
				break;

			case shash(L"-challenge"):
				challenge = argv[i + 1];
				++i;
				break;

			case shash(L"-hashalg"):
				webAuthNClientData.pwszHashAlgId = argv[i + 1];
				hashAlg = argv[i + 1];
				++i;
				break;

			case shash(L"-origin"):
				origin = argv[i + 1];
				++i;
				break;

			case shash(L"-timeout"):
				webAuthNMakeCredentialOptions.dwTimeoutMilliseconds = wcstol(argv[i + 1], NULL, 0);
				webAuthNAssertionOptions.dwTimeoutMilliseconds = wcstol(argv[i + 1], NULL, 0);
				++i;
				break;

			case shash(L"-attach"):
				webAuthNMakeCredentialOptions.dwAuthenticatorAttachment |= wcstol(argv[i + 1], NULL, 0);
				webAuthNAssertionOptions.dwAuthenticatorAttachment |= wcstol(argv[i + 1], NULL, 0);
				++i;
				break;

			case shash(L"-resident"):
				webAuthNMakeCredentialOptions.bRequireResidentKey = TRUE;
				break;

			case shash(L"-verify"):
				webAuthNMakeCredentialOptions.dwUserVerificationRequirement |= wcstol(argv[i + 1], NULL, 0);
				webAuthNAssertionOptions.dwUserVerificationRequirement |= wcstol(argv[i + 1], NULL, 0);
				++i;
				break; 

			case shash(L"-convey"):
				webAuthNMakeCredentialOptions.dwAttestationConveyancePreference |= wcstol(argv[i + 1], NULL, 0);
				++i;
				break;

			case shash(L"-hmacsecret"):	{
					fHmacSecret = TRUE;
					WEBAUTHN_EXTENSION hmacSecret = {
						WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
						sizeof(BOOL),
						&fHmacSecret,
					};
					extensions.push_back(hmacSecret);
				}
				break;

			case shash(L"-exclude"): {
					WEBAUTHN_CREDENTIAL_EX excludedCred = {
						WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
						0,
						nullptr,
						WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
						wcstol(argv[i + 1], NULL, 0),
					};
					++i;
					excludedCreds.push_back(excludedCred);
				}
				break;

			default:
				wprintf(L"Unknown option %s\n", argv[i]);
				PrintHelp(argv[0]);
				return 0;
		}
	}
	
	LPCWSTR format = L"{\"challenge\":\"%s\",\"clientExtensions\":\"{}\",\"hashAlgorithm\":\"%s\",\"origin\":\"%s\",\"type\":\"webauthn.create\"}";
	wchar_t clientDataJSON[1024];
	webAuthNClientData.cbClientDataJSON = wsprintfW(clientDataJSON, format, challenge, hashAlg, origin);
	webAuthNClientData.pbClientDataJSON = (PBYTE) clientDataJSON;

	if (coseParams.size() == 0 ) 
	{
		WEBAUTHN_COSE_CREDENTIAL_PARAMETER coseParam = {
			WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, // Structure version
			WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, // "public-key" string constant
			WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
		};
		coseParams.push_back(coseParam);
	}

	WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyCredParams = {
		static_cast<DWORD>(coseParams.size()), coseParams.data() 
	};

	if (excludedCreds.size() != 0)
	{
		pExcludeCredentials = excludedCreds.data();
		for (DWORD i = 0; i < excludedCreds.size(); i++) {
			excludedCredsPtrs.push_back(&pExcludeCredentials[i]);
		}
		excludedCredsList.cCredentials = excludedCreds.size();
		excludedCredsList.ppCredentials = excludedCredsPtrs.data();
		webAuthNMakeCredentialOptions.pExcludeCredentialList = &excludedCredsList;
	}

	if (extensions.size() != 0)
	{
		webAuthNMakeCredentialOptions.Extensions.cExtensions = extensions.size();
		webAuthNMakeCredentialOptions.Extensions.pExtensions = extensions.data();
	}

	WEBAUTHN_CREDENTIAL_ATTESTATION* pWebAuthNCredentialAttestation = nullptr;
	HRESULT hr = E_FAIL;
	BOOL success = FALSE;
	if (0 == wcscmp(argv[1], L"attest")) {

		hr = WebAuthNAuthenticatorMakeCredential(
			GetForegroundWindow(), &rPInformation, &userInformation, &pubKeyCredParams,
			&webAuthNClientData, &webAuthNMakeCredentialOptions,
			&pWebAuthNCredentialAttestation);

		if (SUCCEEDED(hr) && nullptr != pWebAuthNCredentialAttestation)
		{
			BOOL success = FALSE;
			success = WriteCredentialData(L"attest_authdata", pWebAuthNCredentialAttestation->pbAuthenticatorData, pWebAuthNCredentialAttestation->cbAuthenticatorData);
			success = WriteCredentialData(L"attestation", pWebAuthNCredentialAttestation->pbAttestation, pWebAuthNCredentialAttestation->cbAttestation);
			success = WriteCredentialData(L"attestationObj", pWebAuthNCredentialAttestation->pbAttestationObject, pWebAuthNCredentialAttestation->cbAttestationObject);
			success = WriteCredentialData(L"credentialId", pWebAuthNCredentialAttestation->pbCredentialId, pWebAuthNCredentialAttestation->cbCredentialId);

			WEBAUTHN_CREDENTIAL_EX credential = {
				WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
				pWebAuthNCredentialAttestation->cbCredentialId,
				pWebAuthNCredentialAttestation->pbCredentialId,
				WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
				pWebAuthNCredentialAttestation->dwUsedTransport,
			};
			WebAuthNFreeCredentialAttestation(pWebAuthNCredentialAttestation);
		}
	}

	else if (0 == wcscmp(argv[1], L"assert"))
	{
		PWEBAUTHN_ASSERTION pWebAuthNAssertion = nullptr;
		hr = WebAuthNAuthenticatorGetAssertion(
			GetForegroundWindow(), rPInformation.pwszId, &webAuthNClientData,
			&webAuthNAssertionOptions, &pWebAuthNAssertion);
		if (SUCCEEDED(hr) && nullptr != pWebAuthNAssertion)
		{
			success = WriteCredentialData(L"assert_authdata", pWebAuthNAssertion->pbAuthenticatorData, pWebAuthNAssertion->cbAuthenticatorData);
			success = WriteCredentialData(L"signature", pWebAuthNAssertion->pbSignature, pWebAuthNAssertion->cbSignature);
			success = WriteCredentialData(L"userid", pWebAuthNAssertion->pbUserId, pWebAuthNAssertion->cbUserId);
			WebAuthNFreeAssertion(pWebAuthNAssertion);
		}
	}
	else
	{
		PrintHelp(argv[0]);
		return 0;
	}

	if (S_OK != hr)
		wprintf(L"Error %s", WebAuthNGetErrorName(hr));
}


