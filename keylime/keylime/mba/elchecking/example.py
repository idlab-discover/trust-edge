import re
import typing

from . import policies, tests

# The Example class is an example of a policy for checking boot event logs
# against reference state.  This policy checks:
# - that SecureBoot was enabled
# - that a good BIOS, shim, grub, and kernel were run
# - that only good keys are allowed
# - that all known bad keys are forbidden
# - the initial ramdisk contents and kernel command line were good
#
# This policy expects the reference state to be a dict created by `json.load`
# containing the following.
# scrtm_and_bios - list of allowed {
#    scrtm - digest for PCR 0 event type EV_S_CRTM_VERSION
#    platform_firmware - sequence of digest for PCR 0 event type EV_EFI_PLATFORM_FIRMWARE_BLOB
# }
# pk - list of allowed PK keys
# kek - list of allowed KEK keys
# db - list of allowed db keys
# dbx - list of required dbx keys
# mokdig - list of allowed digests of MoKList (PCR 14 EV_IPL)
# mokxdig - list of allowed digests of MoKListX (PCR 14 EV_IPL)
# kernels - list of allowed {
#   shim_authcode_sha256: 0xhex (for PCR 4 EV_EFI_BOOT_SERVICES_APPLICATION),
#   grub_authcode_sha256: 0xhex (for PCR 4 EV_EFI_BOOT_SERVICES_APPLICATION),
#   kernel_authcode_sha256: 0xhex (for PCR 4 EV_EFI_BOOT_SERVICES_APPLICATION),
#   initrd_plain_sha256: 0xhex (for PCR 9 EV_IPL),
#   kernel_cmdline: regex (for PCR 8 EV_IPL event.Event)
# }
# Here 0xhex is a string starting with '0x' and continuing with lowercase
# hex digits; in the case of a hash value, this includes leading zeros as
# needed to express the full number of bytes the hash function is defined
# to produce.
# A digest is a map from hash-algorithm-name (sha1 or sha256) to 0xhex.
# A key is {SignatureOwner: UUID, SignatureData: 0xhex}.

# First, define some helper functions for checking that the refstate is valid.
# They raise Exception when something invalid is encountered.

hex_pat = re.compile("0x[0-9a-f]+")


def hex_test(dat: typing.Any) -> bool:
    if isinstance(dat, str) and hex_pat.fullmatch(dat):
        return True
    raise Exception(f"{dat!r} is not 0x followed by some lowercase hex digits")


digest_type_test = tests.dict_test(tests.type_test(str), hex_test)

allowed_scrtm_and_bios_test = tests.obj_test(
    scrtm=digest_type_test, platform_firmware=tests.list_test(digest_type_test)
)

allowed_scrtm_and_bios_list_test = tests.list_test(allowed_scrtm_and_bios_test)

allowed_kernel_test = tests.obj_test(
    shim_authcode_sha256=hex_test,
    grub_authcode_sha256=hex_test,
    kernel_authcode_sha256=hex_test,
    initrd_plain_sha256=hex_test,
    kernel_cmdline=tests.type_test(str),
)

allowed_kernel_list_test = tests.list_test(allowed_kernel_test)

shim_authcode_sha256_no_secureboot = tests.obj_test(
    shim_authcode_sha256=hex_test,
    grub_authcode_sha256=hex_test,
    vmlinuz_plain_sha256=hex_test,
    initrd_plain_sha256=hex_test,
    kernel_cmdline=tests.type_test(str),
)

allowed_kernel_list_test_no_secureboot = tests.list_test(shim_authcode_sha256_no_secureboot)


class Example(policies.Policy):
    relevant_pcr_indices = frozenset(list(range(10)) + [14])

    def get_relevant_pcrs(self) -> typing.FrozenSet[int]:
        return self.relevant_pcr_indices

    def refstate_to_test(self, refstate: policies.RefState) -> tests.Test:
        """Return the boot event log test corresponding to the given refstate
        The given refstate is expected to be Python data coming from `json.load`"""
        if not isinstance(refstate, dict):
            raise Exception(f"Expected refstate to be a Python dict but instead got this Python value: {refstate!r}")

        dispatcher = tests.Dispatcher(("PCRIndex", "EventType"))

        def bsa_test(kernel: typing.Dict[str, str]) -> tests.Test:
            return tests.TupleTest(*[
                tests.DigestTest({"sha256": string_strip0x(kernel["shim_authcode_sha256"])}),
                tests.DigestTest({"sha256": string_strip0x(kernel["grub_authcode_sha256"])}),
                tests.DigestTest({"sha256": string_strip0x(kernel["kernel_authcode_sha256"])}),
            ])

        events_final = tests.DelayToFields(tests.FieldsTest(bsas=bsa_test(refstate.get("kernels")[0])),"bsas")

        # We only expect one EV_NO_ACTION event at the start.
        dispatcher.set((0, "EV_NO_ACTION"), tests.AcceptAll())
        dispatcher.set((0, "EV_S_CRTM_CONTENTS"), tests.AcceptAll())
        dispatcher.set((0, "EV_S_CRTM_VERSION"), tests.AcceptAll())
        dispatcher.set((0, "EV_EFI_PLATFORM_FIRMWARE_BLOB"), tests.AcceptAll())
        dispatcher.set((1,"EV_NONHOST_CONFIG"), tests.AcceptAll())
        dispatcher.set((1,"EV_EFI_VARIABLE_BOOT"), tests.AcceptAll())
        dispatcher.set((5,"EV_EFI_GPT_EVENT"), tests.AcceptAll())
        dispatcher.set((14,"EV_IPL"), tests.AcceptAll())
        dispatcher.set((0,"EV_POST_CODE"), tests.AcceptAll())
        dispatcher.set((2,"EV_NONHOST_INFO"), tests.AcceptAll())
        dispatcher.set((4,"EV_EFI_ACTION"), tests.AcceptAll())
        dispatcher.set((1,"EV_EFI_VARIABLE_DRIVER_CONFIG"), tests.AcceptAll())
        dispatcher.set((1,"EV_EFI_HANDOFF_TABLES"), tests.AcceptAll())
        dispatcher.set((7,"EV_EFI_VARIABLE_DRIVER_CONFIG"), tests.AcceptAll())
        dispatcher.set((1,"EV_PLATFORM_CONFIG_FLAGS"), tests.AcceptAll())
        dispatcher.set((6,"EV_COMPACT_HASH"), tests.AcceptAll())
        dispatcher.set((4,"EV_SEPARATOR"), tests.AcceptAll())
        dispatcher.set((1,"EV_SEPARATOR"), tests.AcceptAll())
        dispatcher.set((7,"EV_SEPARATOR"), tests.AcceptAll())
        dispatcher.set((4, "EV_EFI_BOOT_SERVICES_APPLICATION"), events_final.get("bsas"))
        dispatcher.set((0,"EV_SEPARATOR"), tests.AcceptAll())
        dispatcher.set((6,"EV_SEPARATOR"), tests.AcceptAll())
        dispatcher.set((3,"EV_SEPARATOR"), tests.AcceptAll())
        dispatcher.set((9,"EV_IPL"), tests.AcceptAll())
        dispatcher.set((0,"EV_NONHOST_INFO"), tests.AcceptAll())
        dispatcher.set((5,"EV_EFI_ACTION"), tests.AcceptAll())
        dispatcher.set((7,"EV_EFI_VARIABLE_AUTHORITY"), tests.AcceptAll())
        dispatcher.set((2,"EV_SEPARATOR"), tests.AcceptAll())
        dispatcher.set((5,"EV_SEPARATOR"), tests.AcceptAll())
        dispatcher.set((8,"EV_IPL"), tests.AcceptAll())

        
        events_test = tests.FieldTest(
            "events",
            tests.And(events_final.get_initializer(), tests.IterateTest(dispatcher, show_elt=True), events_final),
            show_name=False,
        )
        return events_test


def string_strip0x(con: str) -> str:
    if con.startswith("0x"):
        return con[2:]
    raise Exception(f"{con!r} does not start with 0x")


def digest_strip0x(digest: typing.Dict[str, str]) -> tests.Digest:
    digest_type_test(digest)
    return {alg: string_strip0x(val) for alg, val in digest.items()}


def digests_strip0x(digests: typing.List[typing.Dict[str, str]]) -> typing.List[tests.Digest]:
    tests.type_test(list)(digests)
    return list(map(digest_strip0x, digests))


def sig_strip0x(sig: typing.Dict[str, str]) -> tests.Signature:
    tests.obj_test(SignatureOwner=tests.type_test(str), SignatureData=tests.type_test(str))(sig)
    return {"SignatureOwner": sig["SignatureOwner"], "SignatureData": string_strip0x(sig["SignatureData"])}


def sigs_strip0x(sigs: typing.Iterable[typing.Dict[str, str]]) -> typing.List[tests.Signature]:
    tests.type_test(typing.Iterable)(sigs)
    return list(map(sig_strip0x, sigs))


policies.register("example", Example())
