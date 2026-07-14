import abc
import enum
import os
import fido2.pcsc
from multiprocessing import Process, Queue
from typing import ClassVar, List, Optional
from unittest import TestCase

from fido2.pcsc import CtapPcscDevice

from fido2applet.jvm_util import resolve_jc_home, start_jvm
from fido2applet.paths import fido2_jar_dir, repo_root


class CommandType(enum.Enum):
    APPLET_REINSTALL = 0
    DIRECT_COMMUNICATE = 1
    SOFT_RESET = 2


class LogPrintHandler:
    level = 0
    msg = None

    def handle(self, r):
        msg = r.msg % r.args
        if msg != self.msg:
            self.msg = msg
            print(msg)


class TestModes(enum.Enum):
    PCSC = "pcsc"
    RAW = "raw"


class JCardSimTestCase(TestCase, abc.ABC):
    MODE: TestModes = TestModes.RAW

    q_in: ClassVar[Queue]
    q_out: ClassVar[Queue]
    p: ClassVar[List[Process]]

    DEBUG_PORT = 5005
    SUSPEND_ON_LAUNCH = False
    LOG_ABSOLUTELY_EVERYTHING = False

    @classmethod
    def start_jvm(cls):
        import jpype.imports  # noqa: F401

        my_path = str(repo_root())
        path_to_jars = str(fido2_jar_dir())
        if not os.path.isdir(path_to_jars):
            raise ValueError(
                f"Applet JARs not built - run ./gradlew :applets:fido2:jar :applets:fido2:testJar "
                f"(missing {path_to_jars})"
            )
        jars = os.listdir(path_to_jars)
        main_jars = []
        test_jars = []
        for jar in jars:
            if jar.startswith('fido2applet-tests-'):
                test_jars.append(jar)
            elif jar.startswith('fido2applet-'):
                main_jars.append(jar)
        if len(main_jars) == 0:
            raise ValueError("Applet not built - run ./gradlew :applets:fido2:jar")
        elif len(main_jars) > 1:
            raise ValueError("More than one main jar in build/libs - remove all but one")
        if len(test_jars) == 0:
            raise ValueError("Tests not built - run ./gradlew :applets:fido2:testJar")
        elif len(test_jars) > 1:
            raise ValueError("More than one test jar in build/libs - remove all but one")

        jc_home = os.environ.get('JC_HOME')
        if jc_home is None:
            jc_home = resolve_jc_home(my_path)
        elif not os.path.isabs(jc_home):
            jc_home = os.path.abspath(os.path.join(my_path, jc_home))
        jc_jars = os.path.join(jc_home, 'lib')
        if not os.path.isdir(jc_jars):
            raise ValueError(f"JC_HOME lib not found: {jc_jars}")

        classpath = [
            os.path.abspath(os.path.join(path_to_jars, main_jars[0])),
            os.path.abspath(os.path.join(path_to_jars, test_jars[0])),
        ]
        classpath += [
            os.path.join(jc_jars, x) for x in os.listdir(jc_jars)
        ]

        suspend_char = 'y' if cls.SUSPEND_ON_LAUNCH else 'n'

        jvm_args = []
        if cls.SUSPEND_ON_LAUNCH:
            jvm_args.append(
                "-agentlib:jdwp=transport=dt_socket,server=y,"
                f"suspend={suspend_char},address={cls.DEBUG_PORT}"
            )

        start_jvm(*jvm_args, classpath=classpath)

    @classmethod
    def process(cls, VSim, sim, command_type, command) -> Optional[list[int]]:
        if command_type == CommandType.APPLET_REINSTALL:
            sim.resetRuntime()
            sim.reset()
            if isinstance(command, tuple):
                VSim.installApplet(sim, command[0], command[1])
            else:
                VSim.installApplet(sim, command)
            return None
        elif command_type == CommandType.SOFT_RESET:
            VSim.softReset(sim)
            return None
        elif command_type == CommandType.DIRECT_COMMUNICATE:
            result = VSim.transmitCommand(sim, bytes(command))
            return [(x + 256) % 256 for x in result]
        else:
            return None

    @classmethod
    def launch_sim(cls, incoming_q: Queue, outgoing_q: Queue, startup_q: Queue):
        cls.start_jvm()
        from us.q3q.fido2 import VSim

        if cls.MODE in (TestModes.PCSC,):
            sim = VSim.startBackgroundSimulator()
        else:
            sim = VSim.startForegroundSimulator()
        VSim.installApplet(sim, bytes())

        startup_q.put(None)
        while True:
            command_type, command = incoming_q.get(block=True)
            if command_type == CommandType.APPLET_REINSTALL and command is None:
                break
            outgoing_q.put(cls.process(VSim, sim, command_type, command))

    @classmethod
    def setUpClass(cls) -> None:
        if cls.LOG_ABSOLUTELY_EVERYTHING:
            fido2.pcsc.logger.setLevel(0)
            fido2.pcsc.logger.disabled = False
            fido2.pcsc.logger.isEnabledFor = lambda x: True
            fido2.pcsc.logger.manager.disable = 0
            fido2.pcsc.logger.addHandler(LogPrintHandler())
            fido2.pcsc.logger._cache = {}
        cls.q_in = Queue(maxsize=1)
        cls.q_out = Queue(maxsize=1)
        q_startup = Queue(maxsize=1)
        cls.p = [Process(target=cls.launch_sim, args=(cls.q_out, cls.q_in, q_startup))]
        cls.p[0].start()
        q_startup.get(block=True)

    @classmethod
    def tearDownClass(cls) -> None:
        for p in cls.p:
            print(f"Killing {p}")
            p.kill()
            p.join()
        cls.p = []

    def setUp(self, install_params: Optional[bytes | tuple[bytes, Optional[bytes]]] = None) -> None:
        assert self.p[0].is_alive()
        # Tuple form: (fido_cbor_params, ndef_params). ndef_params=None skips NDEF install.
        # Bare bytes (or None): FIDO params with the default NDEF stub install.
        explicit_ndef = isinstance(install_params, tuple)
        ndef_params: Optional[bytes] = None
        if explicit_ndef:
            install_params, ndef_params = install_params
        if install_params is None:
            install_params = bytes()
        ip_len = len(install_params)
        install_params = bytes([1, 95, 1, 86, ip_len]) + install_params
        command: bytes | tuple[bytes, Optional[bytes]] = install_params
        if explicit_ndef:
            command = (install_params, ndef_params)
        self.q_out.put((CommandType.APPLET_REINSTALL, command))
        self.q_in.get(block=True)

    def tearDown(self) -> None:
        if self.q_in.full():
            self.q_in.get()

    def softResetCard(self) -> None:
        self.q_out.put((CommandType.SOFT_RESET, None))
        self.q_in.get(block=True)

    def transmit_apdu(self, apdu: bytes) -> bytes:
        self.q_out.put((CommandType.DIRECT_COMMUNICATE, list(apdu)))
        return bytes(self.q_in.get(block=True))


class FakeSCConnection:
    q_in: Queue
    q_out: Queue

    def __init__(self, q_in: Queue, q_out: Queue):
        self.q_in = q_in
        self.q_out = q_out

    def connect(self):
        pass

    def disconnect(self):
        pass

    def transmit(self, b, protocol=None):
        self.q_out.put((CommandType.DIRECT_COMMUNICATE, b))
        response = self.q_in.get(block=True)

        sw1 = (response[-2] + 256) % 256
        sw2 = (response[-1] + 256) % 256
        data = [(x + 256) % 256 for x in response[:-2]]

        return list(data), sw1, sw2
