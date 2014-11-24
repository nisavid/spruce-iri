"""Duck types

.. seealso::
    :mod:`Spruce duck types <spruce.lang._datatypes._ducktypes>`

"""

__copyright__ = "Copyright (C) 2014 Ivan D Vasin"
__docformat__ = "restructuredtext"

import re as _re

import goosetypes as _goose


class Uri(_goose.GooseType):

    """A URI

    .. seealso:: :rfc:`URI Syntax Components <3986#section-3>`

    """

    @classmethod
    def displayname(cls):
        return 'URI'

    @classmethod
    def _type_issubclass(cls, type):
        return issubclass(type, basestring)

    @classmethod
    def _value_isinstance(cls, value):
        # NOTE: :mod:`urllib` and :mod:`urlparse` handle valid URIs, but they
        #   do not provide a means to thoroughly validate URIs
        return bool(cls._URI_RE.match(value))

    _HEXDIG_RANGE = r'0-9A-Fa-f'

    _PCT_ENCODED_RE = _re.compile(r'%[{hexdig_range}]{{2}}$'
                                   .format(hexdig_range=_HEXDIG_RANGE))

    _GENDELIMS_RANGE = r':/?#\[\]@'

    _GENDELIMS_RE = _re.compile(r'[{}]'.format(_GENDELIMS_RANGE))

    _SUBDELIMS_RANGE = r"!$&'()*+,;="

    _SUBDELIMS_RE = _re.compile(r'[{}]'.format(_SUBDELIMS_RANGE))

    _RESERVED_RANGE = _GENDELIMS_RANGE + _SUBDELIMS_RANGE

    _RESERVED_RE = _re.compile(r'[{}]'.format(_RESERVED_RANGE))

    _UNRESERVED_RANGE = r'\w\-.~'

    _UNRESERVED_RE = _re.compile(r'[{}]'.format(_UNRESERVED_RANGE))

    _SCHEME_RE = _re.compile(r'[A-Za-z][0-9A-Za-z+-.]*$')

    _USERINFO_RE = \
        _re.compile(r'(?:[{unreserved_range}]|{pct_encoded})+'
                     r'(?::(?:[{unreserved_range}:]|{pct_encoded})+)?$'
                     .format(pct_encoded=_PCT_ENCODED_RE.pattern[:-1],
                             unreserved_range=_UNRESERVED_RANGE))

    _IP4_DEC_OCTET_RE = _re.compile(r'(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$')

    _IP4_ADDR_RE = \
        _re.compile(r'{dec_octet}(?:.{dec_octet}){{3}}$'
                     .format(dec_octet=_IP4_DEC_OCTET_RE.pattern[:-1]))

    _IP6_H16_RE = _re.compile(r'[{hexdig_range}]{{1,4}}$'
                               .format(hexdig_range=_HEXDIG_RANGE))

    _IP6_LS32_RE = _re.compile(r'(?:(?:{h16}:{h16})|{ip4_addr})$'
                                .format(h16=_IP6_H16_RE.pattern[:-1],
                                        ip4_addr=_IP4_ADDR_RE.pattern[:-1]))

    _IP6_ADDR_RE = \
        _re.compile(r'(?:'
                     r'(?:{h16}:){{6}}{ls32}'
                     r'|::(?:{h16}:){{5}}{ls32}'
                     r'|(?:{h16})?::(?:{h16}:){{4}}{ls32}'
                     r'|(?:(?:{h16}:)?{h16})?::(?:{h16}:){{3}}{ls32}'
                     r'|(?:(?:{h16}:){{0,2}}{h16})?::(?:{h16}:){{2}}{ls32}'
                     r'|(?:(?:{h16}:){{0,3}}{h16})?::{h16}:{ls32}'
                     r'|(?:(?:{h16}:){{0,4}}{h16})?::{ls32}'
                     r'|(?:(?:{h16}:){{0,5}}{h16})?::{h16}'
                     r'|(?:(?:{h16}:){{0,6}}{h16})?::'
                     r')$'
                     .format(h16=_IP6_H16_RE.pattern[:-1],
                             ls32=_IP6_LS32_RE.pattern[:-1]))

    _IPX_ADDR_RE = _re.compile(r'v[{hexdig_range}]\.'
                                r'[{unreserved_range}{subdelims_range}:]+$'
                                .format(hexdig_range=_HEXDIG_RANGE,
                                        subdelims_range=_SUBDELIMS_RANGE,
                                        unreserved_range=_UNRESERVED_RANGE))

    _IP_ADDR_RE = _re.compile(r'\[(?:{ip6_addr}|{ipx_addr})\]$'
                               .format(ip6_addr=_IP6_ADDR_RE.pattern[:-1],
                                       ipx_addr=_IPX_ADDR_RE.pattern[:-1]))

    _HOSTNAME_RE = \
        _re.compile(r'(?:[{unreserved_range}{subdelims_range}]'
                     r'|{pct_encoded})*$'
                     .format(pct_encoded=_PCT_ENCODED_RE.pattern[:-1],
                             subdelims_range=_SUBDELIMS_RANGE,
                             unreserved_range=_UNRESERVED_RANGE))

    _HOST_RE = _re.compile(r'(?:{ip_addr}|{ip4_addr}|{hostname})$'
                            .format(ip_addr=_IP_ADDR_RE.pattern[:-1],
                                    ip4_addr=_IP4_ADDR_RE.pattern[:-1],
                                    hostname=_HOSTNAME_RE.pattern[:-1]))

    _PORT_RE = _re.compile(r'\d+$')

    _AUTHORITY_RE = _re.compile(r'(?:{userinfo}@)?{host}'
                                 r'(?::{port})?$'
                                 .format(userinfo=_USERINFO_RE.pattern[:-1],
                                         host=_HOST_RE.pattern[:-1],
                                         port=_PORT_RE.pattern[:-1]))

    _PATH_CHAR_RE = \
        _re.compile(r'(?:[{unreserved_range}{subdelims_range}:@]'
                     r'|{pct_encoded})$'
                     .format(pct_encoded=_PCT_ENCODED_RE.pattern[:-1],
                             subdelims_range=_SUBDELIMS_RANGE,
                             unreserved_range=_UNRESERVED_RANGE))

    _PATH_SEGMENT_RE = _re.compile(r'{char}*$'
                                    .format(char=_PATH_CHAR_RE.pattern[:-1]))

    _PATH_SEGMENT_NZ_RE = \
        _re.compile(r'{char}+$'.format(char=_PATH_CHAR_RE.pattern[:-1]))

    _PATH_SEGMENT_NZ_NC_RE = \
        _re.compile(r'(?:[{unreserved_range}{subdelims_range}@]'
                     r'|{pct_encoded})+$'
                     .format(pct_encoded=_PCT_ENCODED_RE.pattern[:-1],
                             subdelims_range=_SUBDELIMS_RANGE,
                             unreserved_range=_UNRESERVED_RANGE))

    _PATH_ABEMPTY_RE = \
        _re.compile(r'(?:/{segment})*$'
                     .format(segment=_PATH_SEGMENT_RE.pattern[:-1]))

    _PATH_ROOTLESS_RE = \
        _re.compile(r'{segment_nz}{path_abempty}$'
                     .format(segment_nz=_PATH_SEGMENT_NZ_RE.pattern[:-1],
                             path_abempty=_PATH_ABEMPTY_RE.pattern[:-1]))

    _PATH_ABS_RE = \
        _re.compile(r'/(?:{path_rootless})?$'
                     .format(path_rootless=_PATH_ROOTLESS_RE.pattern[:-1]))

    _PATH_NOSCHEME_RE = \
        _re.compile(r'{segment_nz_nc}{path_abempty}$'
                     .format(segment_nz_nc=_PATH_SEGMENT_NZ_NC_RE.pattern[:-1],
                             path_abempty=_PATH_ABEMPTY_RE.pattern[:-1]))

    _PATH_RE = \
        _re.compile(r'(?:{path_abempty}|{path_abs}|{path_noscheme}'
                     r'|{path_rootless})?$'
                     .format(path_abempty=_PATH_ABEMPTY_RE.pattern[:-1],
                             path_abs=_PATH_ABS_RE.pattern[:-1],
                             path_noscheme=_PATH_NOSCHEME_RE.pattern[:-1],
                             path_rootless=_PATH_ROOTLESS_RE.pattern[:-1]))

    _HIER_PART_RE = \
        _re.compile(r'(?://{authority}{path_abempty}|{path_abs}'
                     r'|{path_rootless})?$'
                     .format(authority=_AUTHORITY_RE.pattern[:-1],
                             path_abempty=_PATH_ABEMPTY_RE.pattern[:-1],
                             path_abs=_PATH_ABS_RE.pattern[:-1],
                             path_rootless=_PATH_ROOTLESS_RE.pattern[:-1]))

    _QUERY_RE = _re.compile(r'(?:{path_char}|[/?])*$'
                             .format(path_char=_PATH_CHAR_RE.pattern[:-1]))

    _FRAGMENT_RE = _re.compile(r'(?:{path_char}|[/?])*$'
                                .format(path_char=_PATH_CHAR_RE.pattern[:-1]))

    _URI_RE = _re.compile(r'{scheme}:{hier_part}(?:\?{query})?'
                           r'(?:#{fragment})?$'
                           .format(scheme=_SCHEME_RE.pattern[:-1],
                                   hier_part=_HIER_PART_RE.pattern[:-1],
                                   query=_QUERY_RE.pattern[:-1],
                                   fragment=_FRAGMENT_RE.pattern[:-1]))


class UriReference(Uri):

    """A URI reference

    .. seealso:: :rfc:`URI Usage: URI Reference <3986#section-4.1>`

    """

    @classmethod
    def displayname(cls):
        return 'URI reference'

    @classmethod
    def _value_isinstance(cls, value):
        return bool(cls._URI_REF_RE.match(value))

    _REL_PART_RE = \
        _re.compile(r'(?://{authority}{path_abempty}|{path_abs}'
                     r'|{path_noscheme})?$'
                     .format(authority=Uri._AUTHORITY_RE.pattern[:-1],
                             path_abempty=Uri._PATH_ABEMPTY_RE.pattern[:-1],
                             path_abs=Uri._PATH_ABS_RE.pattern[:-1],
                             path_noscheme=Uri._PATH_NOSCHEME_RE.pattern[:-1]))

    _REL_REF_RE = _re.compile(r'{relpart}(?:\?{query})?(?:#{fragment})?$'
                               .format(uri=Uri._URI_RE.pattern[:-1],
                                       relpart=_REL_PART_RE.pattern[:-1],
                                       query=Uri._QUERY_RE.pattern[:-1],
                                       fragment=Uri._FRAGMENT_RE.pattern[:-1]))

    _URI_REF_RE = _re.compile(r'(?:{uri}|{rel_ref})$'
                               .format(uri=Uri._URI_RE.pattern[:-1],
                                       rel_ref=_REL_REF_RE.pattern[:-1]))


class RelativeUriReference(UriReference):

    """A relative URI reference

    .. seealso:: :rfc:`URI Usage: Relative Reference <3986#section-4.2>`

    """

    @classmethod
    def displayname(cls):
        return 'relative URI reference'

    @classmethod
    def _value_isinstance(cls, value):
        return bool(cls._REL_REF_RE.match(value))
