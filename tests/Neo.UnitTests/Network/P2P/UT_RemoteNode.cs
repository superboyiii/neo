// Copyright (C) 2015-2025 The Neo Project.
//
// UT_RemoteNode.cs file belongs to the neo project and is free
// software distributed under the MIT software license, see the
// accompanying file LICENSE in the main directory of the
// repository or http://www.opensource.org/licenses/mit-license.php
// for more details.
//
// Redistribution and use in source and binary forms with or without
// modifications are permitted.

using Akka.IO;
using Akka.TestKit.MsTest;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Neo.Extensions;
using Neo.Network.P2P;
using Neo.Network.P2P.Capabilities;
using Neo.Network.P2P.Payloads;
using System.Net;

namespace Neo.UnitTests.Network.P2P
{
    [TestClass]
    public class UT_RemoteNode : TestKit
    {
        private static NeoSystem _system;

        public UT_RemoteNode()
            : base($"remote-node-mailbox {{ mailbox-type: \"{typeof(RemoteNodeMailbox).AssemblyQualifiedName}\" }}")
        {
        }

        [ClassInitialize]
        public static void TestSetup(TestContext ctx)
        {
            _system = TestBlockchain.GetSystem();
        }

        [TestMethod]
        public void RemoteNode_Test_Abort_DifferentNetwork()
        {
            var connectionTestProbe = CreateTestProbe();
            var remoteNodeActor = ActorOfAsTestActorRef(() => new RemoteNode(_system, new LocalNode(_system), connectionTestProbe, null, null, new ChannelsConfig()));

            var msg = Message.Create(MessageCommand.Version, new VersionPayload
            {
                UserAgent = "".PadLeft(1024, '0'),
                Nonce = 1,
                Network = 2,
                Timestamp = 5,
                Version = 6,
                Capabilities =
                [
                    new ServerCapability(NodeCapabilityType.TcpServer, 25)
                ]
            });

            var testProbe = CreateTestProbe();
            testProbe.Send(remoteNodeActor, new Tcp.Received((ByteString)msg.ToArray()));

            connectionTestProbe.ExpectMsg<Tcp.Abort>();
        }

        [TestMethod]
        public void RemoteNode_Test_Accept_IfSameNetwork()
        {
            var connectionTestProbe = CreateTestProbe();
            var remoteNodeActor = ActorOfAsTestActorRef(() =>
                new RemoteNode(_system,
                    new LocalNode(_system),
                    connectionTestProbe,
                    new IPEndPoint(IPAddress.Parse("192.168.1.2"), 8080), new IPEndPoint(IPAddress.Parse("192.168.1.1"), 8080), new ChannelsConfig()));

            var msg = Message.Create(MessageCommand.Version, new VersionPayload()
            {
                UserAgent = "Unit Test".PadLeft(1024, '0'),
                Nonce = 1,
                Network = TestProtocolSettings.Default.Network,
                Timestamp = 5,
                Version = 6,
                Capabilities =
                [
                    new ServerCapability(NodeCapabilityType.TcpServer, 25)
                ]
            });

            var testProbe = CreateTestProbe();
            testProbe.Send(remoteNodeActor, new Tcp.Received((ByteString)msg.ToArray()));

            var verackMessage = connectionTestProbe.ExpectMsg<Tcp.Write>();

            //Verack
            Assert.AreEqual(3, verackMessage.Data.Count);
        }
    }
}
