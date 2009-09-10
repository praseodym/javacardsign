using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Globalization;

namespace EDLRegister
{
    public class RegisterException : Exception
    {
        public const int ACQUIRE_CONTEXT = 1;

        private RegisterExceptionEventArgs eventArgs;

        public RegisterExceptionEventArgs EventArgs { get { return eventArgs; } }

        public RegisterException(RegisterExceptionEventArgs e) 
        {
            this.eventArgs = e;
        }

        public override string Message
        {
            get
            {
                return eventArgs.Message;
            }
        }
    }

    public class RegisterExceptionEventArgs : EventArgs
    {
        private int type;

        public int Type { get { return type; } }

        public string Message 
        { 
            get 
            {
                CultureInfo currentCulture = Thread.CurrentThread.CurrentCulture;
                switch (currentCulture.ThreeLetterISOLanguageName)
                {
                    case "nld":
                    case "dut":
                    case "nl":
                        return GetDutchError();
                    default:
                        return GetEnglishError();
                }
            } 
        }

        private string GetDutchError()
        {
            switch (type)
            {
                case RegisterException.ACQUIRE_CONTEXT:
                    return "Kan het rijbewijs niet vinden.";
                default:
                    return "Onbekende foutcode.";
            }
        }

        private string GetEnglishError()
        {
            switch (type)
            {
                case RegisterException.ACQUIRE_CONTEXT:
                    return "Can not find driving license.";
                default:
                    return "Unknown error code.";
            }
        }

        public RegisterExceptionEventArgs(int type)
        {
            this.type = type;
        }
    }
}
