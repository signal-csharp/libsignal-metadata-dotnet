using Google.Protobuf;
using libsignal;
using libsignal.ecc;

namespace libsignalmetadatadotnet.certificate
{
    public class SenderCertificate
    {
        public ServerCertificate Signer { get; }
        public ECPublicKey Key { get; }
        public int SenderDeviceId { get; }
        public string? SenderUuid { get; }
        public string? SenderE164 { get; }
        public string? Sender
        {
            get
            {
                return SenderE164 ?? SenderUuid ?? null;
            }
        }
        public long Expiration { get; }

        public byte[] Serialized { get; }
        public byte[] Certificate { get; }
        public byte[] Signature { get; }

        public SenderCertificate(byte[] serialized)
        {
            try
            {
                var wrapper = libsignalmetadata.protobuf.SenderCertificate.Parser.ParseFrom(serialized);

                if (!wrapper.HasSignature || !wrapper.HasCertificate)
                {
                    throw new InvalidCertificateException("Missing fields");
                }

                var certificate = libsignalmetadata.protobuf.SenderCertificate.Types.Certificate.Parser.ParseFrom(wrapper.Certificate);

                if (certificate.Signer == null ||
                    !certificate.HasIdentityKey ||
                    !certificate.HasSenderDevice ||
                    !certificate.HasExpires ||
                    (!certificate.HasSenderUuid && !certificate.HasSenderE164))
                {
                    throw new InvalidCertificateException("Missing fields");
                }

                Signer         = new ServerCertificate(certificate.Signer.ToByteArray());
                Key            = Curve.decodePoint(certificate.IdentityKey.ToByteArray(), 0);
                SenderUuid = certificate.HasSenderUuid ? certificate.SenderUuid : null;
                SenderE164 = certificate.HasSenderE164 ? certificate.SenderE164 : null;
                SenderDeviceId = (int) certificate.SenderDevice;
                Expiration     = (long) certificate.Expires;

                Serialized  = serialized;
                Certificate = wrapper.Certificate.ToByteArray();
                Signature   = wrapper.Signature.ToByteArray();

            }
            catch (InvalidProtocolBufferException e)
            {
                throw new InvalidCertificateException(e);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidCertificateException(e);
            }
        }
    }
}
