using System;

namespace libsignalmetadatadotnet
{
    public class ProtocolDuplicateMessageException : ProtocolException
    {
        public ProtocolDuplicateMessageException(Exception inner, string? sender, int senderDevice) : base(inner, sender, senderDevice)
        { }
    }
}
