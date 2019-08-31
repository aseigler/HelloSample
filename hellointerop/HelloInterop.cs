using System;
using System.Runtime.InteropServices;

namespace Hello
{
    class Interop
    {
        static readonly Int32 WEBAUTHN_API_VERSION_1 = 1;
        static readonly Int32 WEBAUTHN_API_CURRENT_VERSION = WEBAUTHN_API_VERSION_1;
        static readonly Int32 WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION = 1;
        public struct WEBAUTHN_RP_ENTITY_INFORMATION {
            public Int32 Version;
            public string Id;
            public string Name;
            public string Icon;
        }
        static readonly Int32 WEBAUTHN_MAX_USER_ID_LENGTH = 64;
        static readonly Int32 WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION = 1;
        public struct WEBAUTHN_USER_ENTITY_INFORMATION {
            public Int32 Version;
            public Int32 IdLen;
            public IntPtr Id;
            public string Name;
            public string Icon;
            public string DisplayName;
        }
        static readonly string WEBAUTHN_HASH_ALGORITHM_SHA_256 = "SHA-256";
        static readonly string WEBAUTHN_HASH_ALGORITHM_SHA_384 = "SHA-384";
        static readonly string WEBAUTHN_HASH_ALGORITHM_SHA_512 = "SHA-512";
        static readonly Int32 WEBAUTHN_CLIENT_DATA_CURRENT_VERSION = 1;
        public struct WEBAUTHN_CLIENT_DATA {
            public Int32 Version;
            public Int32 ClientDataJSONLen;
            public IntPtr ClientDataJSON;
            public string HashAlgId;
        }
        static readonly string WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY = "public-key";

        static readonly Int32 WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 = -7;
        static readonly Int32 WEBAUTHN_COSE_ALGORITHM_ECDSA_P384_WITH_SHA384 = -35;
        static readonly Int32 WEBAUTHN_COSE_ALGORITHM_ECDSA_P521_WITH_SHA512 = -36;

        static readonly Int32 WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256 = -257;
        static readonly Int32 WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA384 = -258;
        static readonly Int32 WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA512 = -259;

        static readonly Int32 WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA256 = -37;
        static readonly Int32 WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA384 = -38;
        static readonly Int32 WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA512 = -39;

        static readonly Int32 WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION = 1;
        public struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            public Int32 Version;
            public string CredentialType;
            public long Alg;
        }
        public struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            public Int32 CredentialParametersLength;
            public IntPtr CredentialParameters;
        }
        public struct WEBAUTHN_CREDENTIAL {
            public Int32 Version;
            public ulong IdLength;
            public IntPtr Id;
            public string CredentialType;
        }
        public struct WEBAUTHN_CREDENTIALS {
            public ulong CredentialsLength;
            public IntPtr Credentials;
        }
        public static Int32 WEBAUTHN_CTAP_TRANSPORT_USB = 0x00000001;
        public static Int32 WEBAUTHN_CTAP_TRANSPORT_NFC = 0x00000002;
        public static Int32 WEBAUTHN_CTAP_TRANSPORT_BLE = 0x00000004;
        public static Int32 WEBAUTHN_CTAP_TRANSPORT_TEST = 0x00000008;
        public static Int32 WEBAUTHN_CTAP_TRANSPORT_INTERNAL = 0x00000010;
        public static Int32 WEBAUTHN_CTAP_TRANSPORT_FLAGS_MASK = 0x0000001F;

        public static readonly Int32 WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION = 1;
        public struct WEBAUTHN_CREDENTIAL_EX {
            public Int32 Version;
            public ulong IdLength;
            public IntPtr Id;
            public string CredentialType;
            public ulong Transports;
        }
        public struct WEBAUTHN_CREDENTIAL_LIST {
            public ulong CredentialsLength;
            public IntPtr Credentials;
        }
        public static string WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET = "hmac-secret";
        public struct WEBAUTHN_EXTENSION {
            public string ExtensionIdentifier;
            public ulong ExtensionLength;
            public IntPtr Extension;
        }
        public struct WEBAUTHN_EXTENSIONS {
            public ulong ExtensionsLen;
            public IntPtr Extensions;
        }
        public static Int32 WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY = 0;
        public static Int32 WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM = 1;
        public static Int32 WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 2;
        public static Int32 WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2 = 3;

        public static Int32 WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY = 0;
        public static Int32 WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED = 1;
        public static Int32 WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED = 2;
        public static Int32 WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 3;

        public static Int32 WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY = 0;
        public static Int32 WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE = 1;
        public static Int32 WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT = 2;
        public static Int32 WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT = 3;

        public static Int32 WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1 = 1;
        public static Int32 WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_2 = 2;
        public static Int32 WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3 = 3;
        public static Int32 WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3;
        public struct WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            public Int32 Version;
            public ulong TimeoutMilliseconds;
            public WEBAUTHN_CREDENTIALS CredentialList;
            public WEBAUTHN_EXTENSIONS Extensions;
            public Int32 AuthenticatorAttachment;
            public bool RequireResidentKey;
            public Int32 UserVerificationRequirement;
            public Int32 AttestationConveyancePreference;
            public ulong Flags;
            public IntPtr CancellationId;
            public IntPtr ExcludeCredentialList;
        }
        public static readonly Int32 WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1 = 1;
        public static readonly Int32 WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_2 = 2;
        public static readonly Int32 WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3 = 3;
        public static readonly Int32 WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4 = 4;
        public static readonly Int32 WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4;
        public struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            public Int32 Version;
            public ulong TimeoutMilliseconds;
            public WEBAUTHN_CREDENTIALS CredentialList;
            public WEBAUTHN_EXTENSIONS Extensions;
            public ulong AuthenticatorAttachment;
            public ulong UserVerificationRequirement;
            public ulong Flags;
            public string U2FAppId;
            public IntPtr UsingU2FAppId;
            public IntPtr CancellationId;
            public IntPtr ExcludeCredentialList;
        }
        public static readonly Int32 WEBAUTHN_ATTESTATION_DECODE_NONE = 0;
        public static readonly Int32 WEBAUTHN_ATTESTATION_DECODE_COMMON = 1;
        public static readonly String WEBAUTHN_ATTESTATION_VER_TPM_2_0 = "2.0";
        public struct WEBAUTHN_X5C {
            public ulong DataLength;
            public IntPtr Data;
        }
        public static readonly Int32 WEBAUTHN_COMMON_ATTESTATION_CURRENT_VERSION = 1;
        public struct WEBAUTHN_COMMON_ATTESTATION {
            public Int32 Version;
            public string Alg;
            public ulong COSEAlg;
            public ulong SignatureLength;
            public IntPtr Signature;
            public ulong X5CCount;
            public IntPtr X5C;
            public string Ver;
            public ulong CertInfoLength;
            public IntPtr CertInfo;
            public ulong PubAreaLength;
            public IntPtr PubArea;
        }
        public static readonly String WEBAUTHN_ATTESTATION_TYPE_PACKED = "packed";
        public static readonly String WEBAUTHN_ATTESTATION_TYPE_U2F = "fido-u2f";
        public static readonly String WEBAUTHN_ATTESTATION_TYPE_TPM = "tpm";
        public static readonly String WEBAUTHN_ATTESTATION_TYPE_NONE = "none";

        public static readonly Int32 WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_1 = 1;
        public static readonly Int32 WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_2 = 2;
        public static readonly Int32 WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3 = 3;
        public static readonly Int32 WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION = WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3;
        public struct WEBAUTHN_CREDENTIAL_ATTESTATION {
            public Int32 Version;
            public string FormatType;
            public ulong AuthenticatorDataLength;
            public IntPtr AuthenticatorData;
            public ulong AttestationLength;
            public ulong AttestationDecodeType;
            public IntPtr AttestationDecode;
            public ulong AttestationObjectLength;
            public IntPtr AttestationObject;
            public ulong CredentialIdLength;
            public IntPtr CredentialId;
            public WEBAUTHN_EXTENSIONS Extensions;
            public ulong UsedTransport;
        }
        public static readonly Int32 WEBAUTHN_ASSERTION_CURRENT_VERSION = 1;
        public struct WEBAUTHN_ASSERTION {
            public Int32 Version;
            public ulong AuthenticatorDataLength;
            public IntPtr AuthenticatorData;
            public ulong SignatureLength;
            public IntPtr Signature;
            WEBAUTHN_CREDENTIAL Credential;
            public ulong UserIdLength;
            public IntPtr UserId;
        }
        [DllImport("webauthn.dll")]
        public static extern ulong WebAuthNGetApiVersionNumber();
        [DllImport("webauthn.dll")]
        public static extern bool WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable([MarshalAs(UnmanagedType.U1)] out bool IsUserVerifyingPlatformAuthenticatorAvailable);
        [DllImport("webauthn.dll")]
        public static extern long WebAuthNAuthenticatorMakeCredential();
        [DllImport("webauthn.dll")]
        public static extern long WebAuthNAuthenticatorGetAssertion();
        [DllImport("webauthn.dll")]
        public static extern void WebAuthNFreeCredentialAttestation();
        [DllImport("webauthn.dll")]
        public static extern void WebAuthNFreeAssertion();
        [DllImport("webauthn.dll")]
        public static extern long WebAuthNGetCancellationId(out Guid CancellationId);
        [DllImport("webauthn.dll")]
        public static extern long WebAuthNCancelCurrentOperation(ref Guid CancellationId);
        [DllImport("webauthn.dll")]
        public static extern string WebAuthNGetErrorName(long hr);
        [DllImport("webauthn.dll")]
        public static extern long WebAuthNGetW3CExceptionDOMError(long hr);
        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();
        static void Main(string[] args)
        {
            var ver = WebAuthNGetApiVersionNumber();
            WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(out var available);
            var rp = new WEBAUTHN_RP_ENTITY_INFORMATION
            {
                Version = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
                Id = "login.windows.net",
                Name = "login dot windows dot net",
            };

            var strAseigler = Marshal.StringToHGlobalUni("aseigler");

            var userEntity = new WEBAUTHN_USER_ENTITY_INFORMATION
            {
                Version = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
                Id = strAseigler,
                IdLen = Marshal.SizeOf(strAseigler),
                DisplayName = "Alex Seigler",
                Name = "aseigler"
            };

            var coseParams = new WEBAUTHN_COSE_CREDENTIAL_PARAMETER[0];
            var excludedCreds = new WEBAUTHN_CREDENTIAL_EX[0];
            var excludedCredsList = new WEBAUTHN_CREDENTIAL_LIST[0];

            var webAuthNClientData = new WEBAUTHN_CLIENT_DATA
            {
                Version = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
                HashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256,
            };

            const string challenge = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUgbGF6eSBkb2cu";
            const string hashAlg = "SHA-256";
            const string origin = "login.windows.net";

            webAuthNClientData.ClientDataJSON = Marshal.StringToHGlobalUni(String.Format("{{\"challenge\":\"{0}\",\"clientExtensions\":\"{{}}\",\"hashAlgorithm\":\"{1}\",\"origin\":\"{2}\",\"type\":\"webauthn.create\"}}", challenge, hashAlg, origin));
            webAuthNClientData.ClientDataJSONLen = Marshal.SizeOf(webAuthNClientData.ClientDataJSON);

            var webAuthNMakeCredentialOptions = new WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
            {
                Version = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
                TimeoutMilliseconds = 60000,
                AuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
                RequireResidentKey = false,
                UserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY,
                AttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY,
                Flags = 0,
            };

            var coseParam = new WEBAUTHN_COSE_CREDENTIAL_PARAMETER
            {
                Version = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                Alg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
                CredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            };

            var param = new IntPtr();
            Marshal.StructureToPtr(coseParam, param, false);

            var pubKeyCredParams = new WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
            {
                CredentialParameters = param,
                CredentialParametersLength = Marshal.SizeOf(param),
            };

            var pWebAuthNCredentialAttestation = new WEBAUTHN_CREDENTIAL_ATTESTATION();
            //var hr = WebAuthNAuthenticatorMakeCredential(
            //GetForegroundWindow(), &rPInformation, &userInformation, &pubKeyCredParams,
            //&webAuthNClientData, &webAuthNMakeCredentialOptions,
            //&pWebAuthNCredentialAttestation);
        }
    }
}
