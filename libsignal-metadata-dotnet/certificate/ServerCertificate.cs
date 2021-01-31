using Google.Protobuf;
using libsignal;
using libsignal.ecc;

namespace libsignalmetadatadotnet.certificate
{
    public class ServerCertificate
    {
        public int KeyId { get; }
        public ECPublicKey Key { get; }

        public byte[] Serialized { get; }
        public byte[] Certificate { get; }
        public byte[] Signature { get; }

        public ServerCertificate(byte[] serialized)
        {
            try
            {
                var wrapper = libsignalmetadata.protobuf.ServerCertificate.Parser.ParseFrom(serialized);

                if (!wrapper.HasCertificate || !wrapper.HasSignature)
                {
                    throw new InvalidCertificateException("Missing fields");
                }

                var certificate = libsignalmetadata.protobuf.ServerCertificate.Types.Certificate.Parser.ParseFrom(wrapper.Certificate);

                if (!certificate.HasId || !certificate.HasKey)
                {
                    throw new InvalidCertificateException("Missing fields");
                }

                KeyId       = (int)certificate.Id;
                Key         = Curve.decodePoint(certificate.Key.ToByteArray(), 0);
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
