using libsignal;

namespace libsignalmetadatadotnet
{
    public class ProtocolInvalidKeyException : ProtocolException
    {
        public ProtocolInvalidKeyException(InvalidKeyException inner, string? sender, int senderDevice) : base(inner, sender, senderDevice)
        { }
    }
}
