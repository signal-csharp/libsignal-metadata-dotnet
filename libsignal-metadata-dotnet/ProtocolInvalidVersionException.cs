using libsignal;

namespace libsignalmetadatadotnet
{
    public class ProtocolInvalidVersionException : ProtocolException
    {
        public ProtocolInvalidVersionException(InvalidVersionException inner, string? sender, int senderDevice) : base(inner, sender, senderDevice)
        { }
    }
}
