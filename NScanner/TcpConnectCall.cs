using System.Threading;
using System;
using System.Net;
using System.Net.Sockets;

namespace NScanner
{
    public class TcpConnectCall
    {
        #region member variables
        Socket m_socket;
        bool _mIsConnected;
        bool _mCancelConnect;
        Exception _mConnectFailureException;
        Object m_connectSyncRoot;
        Object m_disposingSyncRoot;
        AutoResetEvent _mConnectCallbackCompleted;
        #endregion

        #region public static methods

        public static void Connect(Socket socket, EndPoint endPoint, int timeoutMs)
        {
            var connectCall = new TcpConnectCall(socket);

            try
            {
                //Need for controlling timeout period introduces us to assynccallback methods
                var connectedCallback = new AsyncCallback(connectCall.ConnectedCallback);


                var result = socket.BeginConnect(endPoint, connectedCallback, connectCall);

                // wait for timeout for connect
                if (result.AsyncWaitHandle.WaitOne(timeoutMs, false) == false)
                {

                    connectCall.CancelConnect();

                    // throw exception
                    throw new Exception("TIME_OUT");
                }
                else
                {

                    if (connectCall._mConnectCallbackCompleted.WaitOne(15000, false) == false)
                    {
                        
                    }

                    Exception connectException = connectCall._mConnectFailureException;
                    if (connectException != null)
                    {
                        //throw new Exception("Exception occurred during connect attempt: " + connectException.Message, connectException);
                        throw new Exception("PORT_CLOSED");
                    }
                    
                }
            }
            finally
            {
                connectCall.Dispose();
            }
        }
        #endregion

        #region constructors - hidden to ensure static access
        private TcpConnectCall(Socket socket)
        {
            _mConnectCallbackCompleted = new AutoResetEvent(false);
            m_disposingSyncRoot = new object();
            m_connectSyncRoot = new object();
            _mConnectFailureException = null;
            _mCancelConnect = false;
            _mIsConnected = false;
            // record socket on which connect attempt will be made
            m_socket = socket;
        }

        #endregion

        #region private methods
        private void Dispose()
        {
            lock (m_disposingSyncRoot)
            {
                _mConnectCallbackCompleted.Close();
                _mConnectCallbackCompleted = null;
            }
        }

        private void CancelConnect()
        {
            lock (m_connectSyncRoot)
            {
                if (_mIsConnected)
                {
                    m_socket.Close();
                    _mIsConnected = false;
                }

                _mCancelConnect = true;
            }
        }

        private void ConnectedCallback(IAsyncResult result)
        {
            lock (m_connectSyncRoot)
            {
                try
                {
                    m_socket.EndConnect(result);
                    // if we get here connected successfully
                    _mIsConnected = true;
                }
                catch (Exception exception)
                {
                    _mConnectFailureException = exception;
                }


                if (_mCancelConnect)
                {
                    m_socket.Close();                    
                    _mIsConnected = false;                    
                }
            }


            lock (m_disposingSyncRoot)
            {
                if (_mConnectCallbackCompleted != null)
                    _mConnectCallbackCompleted.Set();
            }
        }
        #endregion
    }
}