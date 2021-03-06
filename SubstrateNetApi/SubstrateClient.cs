﻿/// <file> SubstrateNetApi\SubstrateClient.cs </file>
/// <copyright file="SubstrateClient.cs" company="mogwaicoin.org">
/// Copyright (c) 2020 mogwaicoin.org. All rights reserved.
/// </copyright>
/// <summary> Implements the substrate client class. </summary>
using Microsoft.VisualStudio.Threading;
using NLog;
using StreamJsonRpc;
using SubstrateNetApi.Exceptions;
using SubstrateNetApi.MetaDataModel;
using SubstrateNetApi.MetaDataModel.Calls;
using SubstrateNetApi.MetaDataModel.Extrinsics;
using SubstrateNetApi.MetaDataModel.Values;
using SubstrateNetApi.TypeConverters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.WebSockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

[assembly: InternalsVisibleTo("SubstrateNetApiTests")]

namespace SubstrateNetApi
{
    /// <summary> A substrate client. </summary>
    /// <remarks> 19.09.2020. </remarks>
    /// <seealso cref="IDisposable"/>
    public class SubstrateClient : IDisposable
    {
        /// <summary> The logger. </summary>
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        /// <summary> _URI of the resource. </summary>
        private readonly Uri _uri;

        /// <summary> The socket. </summary>
        private ClientWebSocket _socket;

        /// <summary> The JSON RPC. </summary>
        private JsonRpc _jsonRpc;

        /// <summary> The connect token source. </summary>
        private CancellationTokenSource _connectTokenSource;
        /// <summary> The request token source. </summary>
        private CancellationTokenSource _requestTokenSource;

        /// <summary> The type converters. </summary>
        private readonly Dictionary<string, ITypeConverter> _typeConverters = new Dictionary<string, ITypeConverter>();

        private HashTypeConverter _hashTypeConverter = new HashTypeConverter();

        private ExtrinsicJsonConverter _extrinsicJsonConverter = new ExtrinsicJsonConverter();

        private ExtrinsicStatusJsonConverter _extrinsicStatusJsonConverter = new ExtrinsicStatusJsonConverter();

        /// <summary> Gets or sets information describing the meta. </summary>
        /// <value> Information describing the meta. </value>
        public MetaData MetaData { get; private set; }

        /// <summary> Gets or sets the genesis hash. </summary>
        /// <value> The genesis hash. </value>
        public Hash GenesisHash { get; private set; }

        /// <summary> Gets the system. </summary>
        /// <value> The system. </value>
        public Modules.System System { get; }

        /// <summary> Gets the chain. </summary>
        /// <value> The chain. </value>
        public Modules.Chain Chain { get; }

        /// <summary> Gets the state. </summary>
        /// <value> The state. </value>
        public Modules.State State { get; }

        /// <summary> Gets the author. </summary>
        /// <value> The author. </value>
        public Modules.Author Author { get; }

        public SubscriptionListener Listener { get; } = new SubscriptionListener();

        /// <summary> Constructor. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <param name="uri"> URI of the resource. </param>
        public SubstrateClient(Uri uri)
        {
            _uri = uri;

            System = new Modules.System(this);
            Chain = new Modules.Chain(this);
            State = new Modules.State(this);
            Author = new Modules.Author(this);

            RegisterTypeConverter(new U8TypeConverter());
            RegisterTypeConverter(new U16TypeConverter());
            RegisterTypeConverter(new U32TypeConverter());
            RegisterTypeConverter(new U64TypeConverter());
            RegisterTypeConverter(new AccountIdTypeConverter());
            RegisterTypeConverter(_hashTypeConverter);
            RegisterTypeConverter(new AccountInfoTypeConverter());
        }

        /// <summary> Registers the type converter described by converter. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <exception cref="ConverterAlreadyRegisteredException"> Thrown when a Converter Already
        ///                                                        Registered error condition occurs. </exception>
        /// <param name="converter"> The converter. </param>
        public void RegisterTypeConverter(ITypeConverter converter)
        {
            if (_typeConverters.ContainsKey(converter.TypeName))
                throw new ConverterAlreadyRegisteredException("Converter for specified type already registered.");

            _typeConverters.Add(converter.TypeName, converter);
        }

        /// <summary> Gets a value indicating whether this object is connected. </summary>
        /// <value> True if this object is connected, false if not. </value>
        public bool IsConnected => _socket?.State == WebSocketState.Open;

        /// <summary> Connects an asynchronous. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <returns> An asynchronous result. </returns>
        public async Task ConnectAsync() => await ConnectAsync(CancellationToken.None);

        /// <summary> Connects an asynchronous. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <param name="token"> A token that allows processing to be cancelled. </param>
        /// <returns> An asynchronous result. </returns>
        public async Task ConnectAsync(CancellationToken token)
        {
            if (_socket != null && _socket.State == WebSocketState.Open)
                return;

            if (_socket == null || _socket.State != WebSocketState.None)
            {
                _jsonRpc?.Dispose();
                _socket?.Dispose();
                _socket = new ClientWebSocket();
            }

            _connectTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token, _connectTokenSource.Token);
            await _socket.ConnectAsync(_uri, linkedTokenSource.Token);
            linkedTokenSource.Dispose();
            _connectTokenSource.Dispose();
            _connectTokenSource = null;
            Logger.Debug("Connected to Websocket.");

            var formatter = new JsonMessageFormatter();

            formatter.JsonSerializer.Converters.Add(_hashTypeConverter);
            formatter.JsonSerializer.Converters.Add(_extrinsicJsonConverter);
            formatter.JsonSerializer.Converters.Add(_extrinsicStatusJsonConverter);

            _jsonRpc = new JsonRpc(new WebSocketMessageHandler(_socket, formatter));
            _jsonRpc.TraceSource.Listeners.Add(new NLogTraceListener());
            _jsonRpc.TraceSource.Switch.Level = SourceLevels.All;
            _jsonRpc.AddLocalRpcTarget(Listener, new JsonRpcTargetOptions() { AllowNonPublicInvocation = false });
            _jsonRpc.StartListening();
            Logger.Debug("Listening to websocket.");

            var result = await State.GetMetaDataAsync(token);
            var metaDataParser = new MetaDataParser(_uri.OriginalString, result);
            MetaData = metaDataParser.MetaData;
            Logger.Debug("MetaData parsed.");

            GenesisHash = await Chain.GetBlockHashAsync(0, token);
            Logger.Debug("Genesis hash parsed.");
        }

        /// <summary> Gets storage asynchronous. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <param name="moduleName"> Name of the module. </param>
        /// <param name="itemName">   Name of the item. </param>
        /// <returns> The storage. </returns>
        public async Task<object> GetStorageAsync(string moduleName, string itemName) => await GetStorageAsync(moduleName, itemName, CancellationToken.None);

        /// <summary> Gets storage asynchronous. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <param name="moduleName"> Name of the module. </param>
        /// <param name="itemName">   Name of the item. </param>
        /// <param name="token">      A token that allows processing to be cancelled. </param>
        /// <returns> The storage. </returns>
        public async Task<object> GetStorageAsync(string moduleName, string itemName, CancellationToken token) => await GetStorageAsync(moduleName, itemName, null, token);

        /// <summary> Gets storage asynchronous. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <param name="moduleName"> Name of the module. </param>
        /// <param name="itemName">   Name of the item. </param>
        /// <param name="parameter">  The parameter. </param>
        /// <returns> The storage. </returns>
        public async Task<object> GetStorageAsync(string moduleName, string itemName, string parameter) => await GetStorageAsync(moduleName, itemName, parameter, CancellationToken.None);

        /// <summary> Gets storage asynchronous. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <exception cref="ClientNotConnectedException">  Thrown when a Client Not Connected error
        ///                                                 condition occurs. </exception>
        /// <exception cref="MissingModuleOrItemException"> Thrown when a Missing Module Or Item error
        ///                                                 condition occurs. </exception>
        /// <exception cref="MissingParameterException">    Thrown when a Missing Parameter error
        ///                                                 condition occurs. </exception>
        /// <exception cref="MissingConverterException">    Thrown when a Missing Converter error
        ///                                                 condition occurs. </exception>
        /// <param name="moduleName"> Name of the module. </param>
        /// <param name="itemName">   Name of the item. </param>
        /// <param name="parameter">  The parameter. </param>
        /// <param name="token">      A token that allows processing to be cancelled. </param>
        /// <returns> The storage. </returns>
        public async Task<object> GetStorageAsync(string moduleName, string itemName, string parameter, CancellationToken token)
        {
            if (_socket?.State != WebSocketState.Open)
                throw new ClientNotConnectedException($"WebSocketState is not open! Currently {_socket?.State}!");

            if (!MetaData.TryGetModuleByName(moduleName, out Module module) || !module.TryGetStorageItemByName(itemName, out Item item))
                throw new MissingModuleOrItemException($"Module '{moduleName}' or Item '{itemName}' missing in metadata of '{MetaData.Origin}'!");

            string method = "state_getStorage";

            if (item.Function?.Key1 != null && parameter == null)
                throw new MissingParameterException($"{moduleName}.{itemName} needs a parameter of type '{item.Function?.Key1}'!");

            string parameters;
            if (item.Function?.Key1 != null)
            {
                byte[] key1Bytes = Utils.KeyTypeToBytes(item.Function.Key1, parameter);
                parameters = "0x" + RequestGenerator.GetStorage(module, item, key1Bytes);
            }
            else
            {
                parameters = "0x" + RequestGenerator.GetStorage(module, item);
            }

            var resultString = await InvokeAsync<string>(method, new object[] { parameters }, token);

            string returnType = item.Function?.Value;

            if (!_typeConverters.ContainsKey(returnType))
                throw new MissingConverterException($"Unknown type '{returnType}' for result '{resultString}'!");

            return _typeConverters[returnType].Create(resultString);
        }

        /// <summary> Gets method asynchronous. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <typeparam name="T"> Generic type parameter. </typeparam>
        /// <param name="method"> The method. </param>
        /// <returns> The method async&lt; t&gt; </returns>
        public async Task<T> GetMethodAsync<T>(string method) => await GetMethodAsync<T>(method, CancellationToken.None);

        /// <summary> Gets method asynchronous. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <typeparam name="T"> Generic type parameter. </typeparam>
        /// <param name="method"> The method. </param>
        /// <param name="token">  A token that allows processing to be cancelled. </param>
        /// <returns> The method async&lt; t&gt; </returns>
        public async Task<T> GetMethodAsync<T>(string method, CancellationToken token) => await InvokeAsync<T>(method, null, token);

        /// <summary> Gets method asynchronous. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <typeparam name="T"> Generic type parameter. </typeparam>
        /// <param name="method">    The method. </param>
        /// <param name="parameter"> The parameter. </param>
        /// <param name="token">     A token that allows processing to be cancelled. </param>
        /// <returns> The method async&lt; t&gt; </returns>
        public async Task<T> GetMethodAsync<T>(string method, string parameter, CancellationToken token) => await InvokeAsync<T>(method, new object[] { parameter }, token);

        internal async Task<string> GetExtrinsicParametersAsync(GenericExtrinsicCall callArguments, Account account, uint tip, uint lifeTime, CancellationToken token)
        {
            Method method = GetMethod(callArguments);

            uint nonce = await System.AccountNextIndexAsync(account.Address, token);

            Era era;
            Hash startEra;

            if (lifeTime == 0)
            {
                era = Era.Create(0, 0);
                startEra = GenesisHash;
            }
            else
            {
                startEra = await Chain.GetFinalizedHeadAsync(token);
                Header finalizedHeader = await Chain.GetHeaderAsync(startEra, token);
                era = Era.Create(lifeTime, finalizedHeader.Number);
            }

            var uncheckedExtrinsic = RequestGenerator.SubmitExtrinsic(true, account, method, era, nonce, tip, GenesisHash, startEra);
            return Utils.Bytes2HexString(uncheckedExtrinsic.Encode(), Utils.HexStringFormat.PREFIXED);
        }

        public Method GetMethod(GenericExtrinsicCall callArguments)
        {
            if (!MetaData.TryGetModuleByName(callArguments.ModuleName, out Module module) || !module.TryGetCallByName(callArguments.CallName, out Call call))
                throw new MissingModuleOrItemException($"Module '{callArguments.ModuleName}' or Item '{callArguments.CallName}' missing in metadata of '{MetaData.Origin}'!");

            if (call.Arguments?.Length > 0 && callArguments == null)
                throw new MissingParameterException($"{callArguments.ModuleName}.{callArguments.CallName} needs {call.Arguments.Length} parameter(s)!");

            return new Method(module, call, callArguments?.Encode());
        }

        /// <summary>
        /// Executes the asynchronous on a different thread, and waits for the result.
        /// </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <exception cref="ClientNotConnectedException"> Thrown when a Client Not Connected error
        ///                                                condition occurs. </exception>
        /// <typeparam name="T"> Generic type parameter. </typeparam>
        /// <param name="method">     The method. </param>
        /// <param name="parameters"> Options for controlling the operation. </param>
        /// <param name="token">      A token that allows processing to be cancelled. </param>
        /// <returns> A T. </returns>
        internal async Task<T> InvokeAsync<T>(string method, object parameters, CancellationToken token)
        {
            if (_socket?.State != WebSocketState.Open)
                throw new ClientNotConnectedException($"WebSocketState is not open! Currently {_socket?.State}!");

            Logger.Debug($"Invoking request[{method}, params: {parameters}] {MetaData?.Origin}");

            _requestTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token, _requestTokenSource.Token);
            var resultString = await _jsonRpc.InvokeWithParameterObjectAsync<T>(method, parameters, linkedTokenSource.Token);
            linkedTokenSource.Dispose();
            _requestTokenSource.Dispose();
            _requestTokenSource = null;
            return resultString;
        }

        /// <summary> Closes an asynchronous. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <returns> An asynchronous result. </returns>
        public async Task CloseAsync() => await CloseAsync(CancellationToken.None);

        /// <summary> Closes an asynchronous. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <param name="token"> A token that allows processing to be cancelled. </param>
        /// <returns> An asynchronous result. </returns>
        public async Task CloseAsync(CancellationToken token)
        {
            _connectTokenSource?.Cancel();
            _requestTokenSource?.Cancel();

            if (_socket != null && _socket.State == WebSocketState.Open)
            {
                _jsonRpc?.Dispose();
                Logger.Debug("Client closed.");
            }
        }

        #region IDisposable Support
        /// <summary> To detect redundant calls. </summary>
        private bool _disposedValue = false;

        /// <summary> This code added to correctly implement the disposable pattern. </summary>
        /// <remarks> 19.09.2020. </remarks>
        /// <param name="disposing"> True to release both managed and unmanaged resources; false to
        ///                          release only unmanaged resources. </param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    new JoinableTaskFactory(new JoinableTaskContext()).Run(CloseAsync);
                    _connectTokenSource?.Dispose();
                    _requestTokenSource?.Dispose();
                    _jsonRpc?.Dispose();
                    _socket?.Dispose();
                    Logger.Debug("Client disposed.");
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                _disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~SubstrateClient()
        // {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        /// <summary> This code added to correctly implement the disposable pattern. </summary>
        /// <remarks> 19.09.2020. </remarks>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion
    }
}
