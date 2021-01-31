using libsignal;

namespace libsignalmetadatadotnet
{
    public class ProtocolInvalidMessageException : ProtocolException
    {
        public ProtocolInvalidMessageException(InvalidMessageException inner, string? sender, int senderDevice) : base(inner, sender, senderDevice)
        { }
    }
}
