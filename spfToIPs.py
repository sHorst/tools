#!/usr/bin/env python3

from spf import AmbiguityWarning, query, RE_MODIFIER, PermError, MAX_RECURSION, TempError
import ipaddress

USAGE = """To convert spf to list of ips:
    % python spfToIPs.py {domain}
    % python spfToIPs.py google.com
"""


class QueryNew(query):
    def __init__(self):
        super().__init__(i='127.0.0.1', s='ultrachaos.de', h='ultrachaos.de')
        pass

    def get_ips1(self, spf, domain, recursion):
        if recursion > MAX_RECURSION:
            raise PermError('Too many levels of recursion')
        try:
            tmp, self.d = self.d, domain
            try:
                return self.get_ips(spf, recursion)
            finally:
                self.d = tmp
        except AmbiguityWarning as x:
            if x.mech:
                self.mech.append(x.mech)
            return []

    def get_ips(self, spf, recursion):
        """Get all IPs connected to this SPF Record.

        Returns (result, mta-status-code, explanation) where
        result in ['fail', 'unknown', 'pass', 'none']
        """

        ips = []

        if not spf:
            return []

        # Split string by space, drop the 'v=spf1'.  Split by all whitespace
        # casuses things like carriage returns being treated as valid space
        # separators, so split() is not sufficient.
        spf = spf.split(' ')
        # Catch case where SPF record has no spaces.
        # Can never happen with conforming dns_spf(), however
        # in the future we might want to give warnings
        # for common mistakes like IN TXT "v=spf1" "mx" "-all"
        # in relaxed mode.
        if spf[0].lower() != 'v=spf1':
            return []

        # Just to make it even more fun, the relevant piece of the ABNF for
        # term separations is *( 1*SP ( directive / modifier ) ), so it's one
        # or more spaces, not just one.  So strip empty mechanisms.
        spf = [mech for mech in spf[1:] if mech]

        # copy of explanations to be modified by exp=
        redirect = None

        # no mechanisms at all cause unknown result, unless
        # overridden with 'default=' modifier
        #
        default = 'neutral'
        mechs = []

        modifiers = []
        # Look for modifiers
        #
        for mech in spf:
            m = RE_MODIFIER.split(mech)[1:]
            if len(m) != 2:
                mechs.append(self.validate_mechanism(mech))
                continue

            mod, arg = m
            if mod in modifiers:
                if mod == 'redirect':
                    raise PermError('redirect= MUST appear at most once', mech)
                print('%s= MUST appear at most once' % mod, mech)
                # just use last one in lax mode
            modifiers.append(mod)
            if mod == 'exp':
                # always fetch explanation to check permerrors
                if not arg:
                    raise PermError('exp has empty domain-spec:', arg)
                arg = self.expand_domain(arg)
                if arg:
                    try:
                        exp = self.get_explanation(arg)
                        if exp and not recursion:
                            # only set explanation in base recursion level
                            self.set_explanation(exp)
                    except:
                        pass
            elif mod == 'redirect':
                self.check_lookups()
                redirect = self.expand_domain(arg)
                if not redirect:
                    raise PermError('redirect has empty domain:', arg)
            elif mod == 'default':
                # default modifier is obsolete
                pass
            elif mod == 'op':
                if not recursion:
                    for v in arg.split('.'):
                        if v:
                            self.options[v] = True
            else:
                # spf rfc: 3.6 Unrecognized Mechanisms and Modifiers
                self.expand(m[1])       # syntax error on invalid macro

        # Evaluate mechanisms
        #
        for mech, m, arg, cidrlength, result in mechs:

            if m == 'include':
                self.check_lookups()
                d = self.dns_spf(arg)
                ips += self.get_ips1(d, arg, recursion + 1)
                continue
            elif m == 'all':
                break

            elif m == 'exists':
                self.check_lookups()
                continue

            elif m == 'a':
                self.check_lookups()
                ips += map(lambda x: ipaddress.ip_address(x), self.dns_a(arg, 'A'))
                ips += map(lambda x: ipaddress.ip_address(x), self.dns_a(arg, 'AAAA'))
                continue

            elif m == 'mx':
                self.check_lookups()
                self.A = 'A'
                ips += map(lambda x: ipaddress.ip_address(x), self.dns_mx(arg))
                self.A = 'AAAA'
                ips += map(lambda x: ipaddress.ip_address(x), self.dns_mx(arg))

                continue

            elif m == 'ip4':
                ips.append(ipaddress.ip_network("%s/%s" % (arg, cidrlength)))
                continue

            elif m == 'ip6':
                ips.append(ipaddress.ip_network("%s/%s" % (arg, cidrlength)))
                continue

            elif m == 'ptr':
                self.check_lookups()
                continue

        else:
            # no matches
            if redirect:
                # Catch redirect to a non-existant SPF record.
                redirect_record = self.dns_spf(redirect)
                if not redirect_record:
                    raise PermError('redirect domain has no SPF record',
                                    redirect)
                # forget modifiers on redirect
                if not recursion:
                    self.exps = dict(self.defexps)
                return self.get_ips1(redirect_record, redirect, recursion)

        return ips


if __name__ == '__main__':
    import getopt
    import sys

    try:
        opts, argv = getopt.getopt(sys.argv[1:], "h", ["help"])
    except getopt.GetoptError as err:
        print(str(err))
        print(USAGE)
        sys.exit(2)

    for o, a in opts:
        if o in ('-h', '--help'):
            print(USAGE)

    if len(argv) == 0:
        print(USAGE)

    elif len(argv) == 1:
        try:
            query = QueryNew()
            ips = query.get_ips(query.dns_spf(argv[0]), True)

            print("\n".join(map(lambda x: str(x), ips)))
        except TempError as x:
            print("Temporary DNS error: ", x)
        except PermError as x:
            print("PermError: ", x)
    else:
        print(USAGE)