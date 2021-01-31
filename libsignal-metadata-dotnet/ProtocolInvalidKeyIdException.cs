using System;

namespace libsignalmetadatadotnet
{
    public class ProtocolInvalidKeyIdException : ProtocolException
    {
        public ProtocolInvalidKeyIdException(Exception inner, string? sender, int senderDevice) : base(inner, sender, senderDevice)
        { }
    }
}
