import json
class PyParseEncoder(json.JSONEncoder):
    # https://stackoverflow.com/a/16984069
    def default(self, obj):
        #print(type(obj))
        if isinstance(obj, ParseResults):
            x = obj.asDict()
            if x.keys():
                obj = x
            else:
                x = obj.asList()
                if len(x) == 1:
                    obj = x[0]
                else:
                    obj = x
        else:
            obj = super(PyParseEncoder, self).default(obj)
        return obj

import re
from pyparsing import *
import pyparsing as pp
import string
import struct
import copy
import subprocess
import os

# The assumption is that code which is run cannot ever break the GPU.
# ^ This makes sense: if a corrupted/malicious program could brick the GPU, that would be very problematic
# ^ Therefore we can e.g. try using unused bits, see what happens - or using the barriers, even though they are not declared as usable for many instructions.
# When it comes to stall cycles and yield etc.
# TODO: Make small program that adds/overlays the control code information on the output of "nvdisasm -hex"
# FIXME: The files are not completely intact, namely some "#" symbols should not be present in sm_35, and TABLES_opex_7 is broken in one entry in sm_70

file = "sm_86_instructions.txt"
file = "sm_86_instructions.txt"
with open(file, "r", encoding="ascii") as f:
    data = f.read()

# Get the subset corresponding to instructions
pre = data[:re.search('CLASS "\w+"', data).start()]
instructions = data[len(pre):]

pp_var_name = Word(alphanums + '._')
pp_dict_name = Combine(Word(alphanums + '._') + Optional('*'), adjacent=False)
pp_table_var_name_orig = Word(alphanums + '._@')
pp_table_var_name = Group(OneOrMore('-' | Word(alphanums + "\"._'/@&?"), stop_on='->'))
pp_word = Word(alphanums + "._/")
pp_number = pp.common.hex_integer | pp.common.integer

# https://stackoverflow.com/a/28726606
INT_DECIMAL      = Regex('(-?(([1-9][0-9]*)|0+))')#.set_parse_action(token_map(int))
INT_BINARY  = Regex('(-?0[bB][_0-1]*)')#.set_parse_action(token_map(int, 2))
INT_OCTAL        = Regex('(-?0[0-7]*)')#.set_parse_action(token_map(int, 8))
INT_HEXADECIMAL  = Regex('(-?0[xX][0-9a-fA-F]*)')#.set_parse_action(token_map(int, 16))
INTEGER          = INT_BINARY | INT_HEXADECIMAL | INT_OCTAL | INT_DECIMAL
FLOAT = Regex('-?([0-9]*[.])?[0-9]+')
#.set_parse_action(pp.common.convert_to_integer)
# TODO: ^ Fix parsing of underscores in literal? (Already fixed for binary)

bitfield = {}
def save_bitfield(test):
    bitfield.update(test)
    return test


entry_entry = Suppress(Optional(Word(string.whitespace))) + SkipTo(';', ignore=QuotedString('"'))
csv_entry = Group(pp.delimited_list(pp_var_name, ',', min=2))
dict_entry = Dict(pp.delimited_list(Group((Suppress(Opt('"')) + pp_dict_name + Suppress(Opt('"'))) + Suppress("=") + INTEGER), ','), asdict=True)

architecture_entries = lambda stop_on=None: OneOrMore(Group(pp_var_name + Or([csv_entry, dict_entry, entry_entry]) + Suppress(";")), stop_on=stop_on)

#def get_list_parser(key_expr=Word(pp.printables), op='=', delim=',', stop_on=None):
#    entry_expr = Group(key_expr + Optional(Suppress(op) + value_expr))
#    list_expr = entry_expr + ZeroOrMore(Suppress(delim) + entry_expr, stop_on=stop_on)
#    return list_expr

# Architecture details
pp_name = Word(alphanums + '._')
pp_special = Combine(pp_name + '+' + pp_name, adjacent=False) | (Suppress('=') + QuotedString('"'))
pp_anything = Suppress(White(min=0)) + SkipTo(Suppress(White(min=0)) + ';', ignore=QuotedString('"'))
pp_value = pp_special | pp.delimited_list(pp_name) | pp_anything

# TODO: Convert relocators to dict?

pp_architecture_key = Word(pp.printables)
#pp_architecture_entry = Group(pp_architecture_key + Optional(Suppress('=') + value_expr))
#pp_architecture_list = ZeroOrMore(get_list_parser(SkipTo(';', ignore=QuotedString('"')), op=Empty()) + Suppress(';'), stop_on='RELOCATORS')
#pp_architecture_list = get_list_parser(SkipTo(';'), delim=';')
pp_simple_dict_expr = Dict(ZeroOrMore(Group(pp_name + pp_value + Suppress(';'))), asdict=True)
get_pp_dict_expr = lambda key=pp_name, value=pp_name, sep='=', end=Empty(), stop_on=None: Dict(ZeroOrMore(Group(key + Suppress(sep) + value + Suppress(end)), stop_on=stop_on), asdict=True)

pp_architecture = Group('ARCHITECTURE' + QuotedString('"'))
pp_architecture_details = Group(Empty().setParseAction(replaceWith('ARCHITECTURE DETAILS')) + pp_simple_dict_expr) #get_pp_dict_expr(pp_name, pp_value, sep=Empty(), end=';')
pp_condition_types = Group('CONDITION TYPES' + get_pp_dict_expr(sep=':'))
pp_parameters = Group('PARAMETERS' + get_pp_dict_expr())
pp_constants = Group('CONSTANTS' + get_pp_dict_expr())
pp_string_map = Group('STRING_MAP' + get_pp_dict_expr(sep='->'))

INT_DECIMAL_parsed      = INT_DECIMAL.copy().set_parse_action(token_map(int))
INT_BINARY_parsed  = INT_BINARY.copy().set_parse_action(token_map(int, 2))
INT_OCTAL_parsed        = INT_OCTAL.copy().set_parse_action(token_map(int, 8))
INT_HEXADECIMAL_parsed  = INT_HEXADECIMAL.copy().set_parse_action(token_map(int, 16))
INTEGER_parsed = INT_BINARY_parsed | INT_HEXADECIMAL_parsed | INT_OCTAL_parsed | INT_DECIMAL_parsed
FLOAT_parsed = FLOAT.copy().set_parse_action(token_map(float))  #('([+-]?(([1-9][0-9]*)|0+))')
# FIXME: ^ Verify that this works as intended.

pp_register_name = pp_name | Combine(Suppress('"') + pp_name + Suppress('"'))
pp_register_lside = INTEGER_parsed #pp.infix_notation(INTEGER | pp_name, [('+', 2, opAssoc.LEFT)])
pp_register_value_lst_assign = pp_register_name + Suppress('(') + pp_register_lside + Suppress('..') + pp_register_lside + Suppress(')') + Optional(Suppress('=') + Suppress('(') + pp_register_lside + Suppress('..') + pp_register_lside + Suppress(')'))
pp_registers_value = pp.delimited_list(Group(pp_register_value_lst_assign | (Combine(pp_register_name + Optional(Suppress('*')), adjacent=False) + Optional(Suppress('=') + pp_register_lside))))

from collections import OrderedDict
def parse_reg(test):
    # In a similar manner to DictSum, we could create some type to hold these ranges.
    c = 0

    result = {}  # OrderedDict()
    for token in test:
        #print(token)
        # TODO: Find more elegant formulation (generalize to always use the last, token+range+range case)
        # print(test)
        if len(token) <= 2:   # Case token or token+value
            if len(token) == 2:  # Case token+value
                c = token[1]
            result[token[0]] = c
            c += 1
        if len(token) == 1+2:  # Case token+range
            for n in range(token[1], token[2]+1):  # +1 for range inclusive
                result[token[0] + str(n)] = c
                c += 1
        if len(token) == 1+2+2:  # Case token+range+range
            c = token[3]
            for n, i in zip(range(token[1], token[2]+1), range(token[3], token[4]+1)):
                assert i == c
                result[token[0] + str(n)] = i
                c += 1
        # TODO: Check if token is already in dict (with another value). What to do in these cases? (Do they have consequences?)
    return result


class DictSum(dict):
    def __init__(self, names, dicts):
        # (Maybe we should really just use a normal dict instead for simplicity?)
        # Dicts should be a lookup table of dicts that may be referenced by a name.
        self._names = names  # <- Just so we do not lose the "subtypes" of this union type.
        for name in names:
            self.update(dicts[name])

    def __repr__(self):
        return ' + '.join(self._names)

register_tables = {}
def parse_reg_assign(test):
    if isinstance(test[1], dict):
        register_tables[test[0]] = test[1]
        return test

    # In case we are not given a dict, it is assumed we are given a union type (sum of types, e.g. "Integer = Integer8 + Integer16 + Integer32 + Integer64;")
    # We just create a new type "Integer", which as an enum contains all the values of the other types. This way of
    # handling, then, does not support 'type checking', which is fine for our purposes as instructions are assumed valid
    # (E.g. if a type/enum "String" has a value "S32", it could do a look-up into Integer,
    # even though String is neither Integer8, Integer16, Integer32 nor Integer 64.)
    test[1:] = [DictSum(test[1:], register_tables)]
    # print(test[0], '=', str(test[1]))
    return parse_reg_assign(test)

pp_registers_value.set_parse_action(parse_reg)
pp_registers0 = pp_name + pp_registers_value + Suppress(';')
pp_registers1 = pp_name + Suppress('=') + pp.delimited_list(pp_register_name, '+') + Suppress(';')
register_assign = (pp_registers0 | pp_registers1).set_parse_action(parse_reg_assign)

pp_registers = Group('REGISTERS' + Dict(ZeroOrMore(Group(register_assign), stop_on='TABLES'), asdict=True)) # get_pp_dict_expr()


pp_regref = Combine(pp_name + '@' + pp_register_name)
pp_tables_key = ('-' | Literal("'/'") | "'&'") | INTEGER_parsed.copy() | pp_regref | pp_name
pp_tables = Group('TABLES' + Dict(ZeroOrMore(Group(pp_name + get_pp_dict_expr(key=Combine(OneOrMore(pp_tables_key, stop_on='->'), adjacent=False, join_string=' '), value=pp_tables_key, sep='->') + Suppress(';'))), asdict=True))

def parse_regref(test):
    keys = test[0].split('@')
    if keys[0] in register_tables:
        if keys[1] in register_tables[keys[0]]:
            # Replace the symbolic refernce with its actual integer value. (Note this discards type information, so it
            #  will not give correct results on any function that gives different outputs for the same value but varying type)
            test[0] = register_tables[keys[0]][keys[1]]
    return test

pp_regref.set_parse_action(parse_regref)

# INTEGER
pp_operation_properties = Group("OPERATION PROPERTIES" + Group(ZeroOrMore(pp_var_name) + Suppress(";")))
pp_operation_predicates = Group("OPERATION PREDICATES" + Group(ZeroOrMore(pp_var_name) + Suppress(";")))

pp_funit_bitfields = Group(Empty().setParseAction(replaceWith('BITFIELDS')) + get_pp_dict_expr(value=QuotedString("'"), sep=White()))
pp_NOPenc = Group("NOP_ENCODING" + get_pp_dict_expr() + Suppress(';'))
pp_funit = Group("FUNIT" + Suppress("uC") + Dict(Group("ISSUE_SLOTS" + Group(OneOrMore(INTEGER)) + Suppress(';')) + Group("ENCODING WIDTH" + INTEGER + Suppress(';')) + pp_funit_bitfields + pp_NOPenc, asdict=True))



# tables = Group("TABLES" + OneOrMore(Group(pp_var_name + OneOrMore(Group(pp_table_var_name + Suppress("->") + (INTEGER | pp_table_var_name_orig)), stop_on=";") + Suppress(";"))))
# pp_relocators = Suppress('RELOCATORS') + ... + Suppress(';')
# pp.delimited_list(pp_key + pp_key + Suppress(';'), ';')
# SkipTo(';', ignore=QuotedString('"'))
test = "Register@RZ -" #"Register@RZ - -> PSEUDO_OPCODE1@MOV"
#print(OneOrMore((White().suppress() & '-' & White().suppress()) | Word(alphanums + "._@'&/\"")).parse_string(test, parse_all=True))
# + pp_funit_bitfields + pp_NOPenc
pp_pre = Dict(pp_architecture + pp_architecture_details + Optional(pp_condition_types) + pp_parameters + pp_constants + Optional(pp_string_map) + pp_registers + pp_tables + pp_operation_properties + pp_operation_predicates + pp_funit, asdict=True)
parse_result = pp_pre.parse_string(pre, parse_all=True)

# bitfields = Dict(OneOrMore(Group(pp_var_name + QuotedString("'"))), asdict=True).set_parse_action(save_bitfield)
#print(json.dumps(parse_result[:150], cls=PyParseEncoder, sort_keys=False, indent=2))


if False:
    architecture = "ARCHITECTURE" & QuotedString('"') + architecture_entries(Literal("CONDITION TYPES")|'PARAMETERS') #OneOrMore(Group(pp_var_name + ... + Suppress(";" & LineEnd() )) , stop_on=Literal("CONDITION TYPES")|'PARAMETERS')
    condition_types = Optional(Group("CONDITION TYPES" + Dict(OneOrMore(Group(pp_var_name + Suppress(":") + pp_var_name)), asdict=True)))
    parameters = Group("PARAMETERS" + Dict(OneOrMore(Group(pp_var_name + Suppress("=") + INTEGER)), asdict=True))
    constants = Group("CONSTANTS" + Dict(OneOrMore(Group(pp_var_name + Suppress("=") + INTEGER)), asdict=True))
    string_map = Optional(Group("STRING_MAP" + OneOrMore(Group(pp_var_name + Suppress("->") + pp_var_name))))
    registers = Group("REGISTERS" + architecture_entries("SIDL_NAMES"))
    #sidl_names = Group("SIDL_NAMES" + pp.delimited_list(pp_var_name, ',') + Suppress(';'))
    #other = Group(OneOrMore(Group(pp_var_name + ... + Suppress(";" & LineEnd() )) , stop_on="TABLES"))
    other = architecture_entries("TABLES")
    tables = Group("TABLES" + OneOrMore(Group(pp_var_name + OneOrMore(Group(pp_table_var_name + Suppress("->") + (INTEGER | pp_table_var_name_orig)), stop_on=";") + Suppress(";"))))
    # tables = Group("TABLES" + OneOrMore(Group(pp_var_name + OneOrMore(Group(pp_table_var_name + Suppress("->") + (INTEGER | pp_table_var_name_orig) + Suppress(LineEnd())), stop_on=";") + Suppress(";"))))
    operation_properties = Group("OPERATION PROPERTIES" + Group(ZeroOrMore(pp_var_name) + Suppress(";")))
    operation_predicates = Group("OPERATION PREDICATES" + Group(ZeroOrMore(pp_var_name) + Suppress(";")))
    funit = Group("FUNIT" + Group(pp_var_name + "ISSUE_SLOTS" + Group(OneOrMore(INTEGER)) + Suppress(';')) + Group("ENCODING WIDTH" + INTEGER + Suppress(';')))
    bitfields = Dict(OneOrMore(Group(pp_var_name + QuotedString("'"))), asdict=True).set_parse_action(save_bitfield)
    NOP_enc = Group("NOP_ENCODING" + pp_var_name + Suppress('=') + ... + Suppress(';'))


    pp_pre = architecture + condition_types + parameters + constants + string_map + registers + other + tables + operation_properties + operation_predicates + funit + bitfields + NOP_enc

# TODO: implement case of float...? (probably not needed as a float "F16Imm-F64Imm" never has a default value)
pp_spec_type_default_value_integer = (INTEGER_parsed + Suppress('/') + INTEGER_parsed | INTEGER) + Optional(Suppress('*'))
pp_spec_type_default_value_string = (pp_name | (Optional(Suppress('"')) + pp_name + Optional(Suppress('"'))))
# pp_spec_type_default_value_any = ...
pp_spec_type_default_value = Suppress('(') + (pp_spec_type_default_value_integer | pp_spec_type_default_value_string) + Suppress(Optional('/PRINT')) + Suppress(')')  #  <- not sure what /PRINT means?
pp_spec_type = Combine(Optional('/') + pp_var_name) + Optional(pp_spec_type_default_value) + Optional(Suppress('*') | Suppress('@'))  # Meaning of @ ? e.g. UImm(13)@:tid
# ^ A type declaration with optional default and possibly being a pointer type.

class Immediate:
    immediate_types = {'F64Imm', 'F32Imm', 'F16Imm', 'RSImm', 'SSImm', 'SImm', 'UImm', 'BITSET'}

    @classmethod
    def is_immediate_type(cls, _type):
        # Alternatively: Check if equals BITSET, or if it starts with F or contains S/U as the fourth last character.
        return _type in cls.immediate_types

    def __init__(self, _type, width, default_value=None):
        assert self.is_immediate_type(_type)
        self._type = _type
        self._width = int(width)
        self._default = int(default_value) if default_value is not None else default_value

    def __repr__(self):
        if self._default is None:
            return self._type + '(' + str(self._width) + ')'
        return self._type + '(' + str(self._width) + '/' + str(self._default) + ')'

    def __index__(self):
        return self._default

    def token(self):
        if self._type.startswith('F'):
            return FLOAT_parsed.copy().set_parse_action(lambda f: Immediate(self._type, self._width, f[0]))
        return INTEGER_parsed.copy().set_parse_action(lambda d: Immediate(self._type, self._width, d[0]))

    def to_bytes(self, length=None, byteorder='little', signed=None):
        assert False
        if length is not None:
            assert length == self._width
        length = self._width



# length, byteorder='little', signed
#def to_bytes(value):


def parse_spec_type(test):
    #key = test[0]
    #if key.startswith('/'):
    #    key = key[1:]

    if Immediate.is_immediate_type(test[0]):
        #print(test)
        # Pattern is type:str, width:int, default:int
        test[1:] = [Immediate(*test)]
        # len(test) == 3:

        # print(test, str(test[1]))
    #elif key in register_tables:
    #    test[1] = register_tables[key]

    return test

pp_spec_type.set_parse_action(parse_spec_type)

def parse_spec_assign(test):
    result = {'name' : test[2], 'dotsep': False}
    type = test[1][0]
    if type.startswith('/'):
        type = type[1:]
        result['dotsep'] = True
    result['type'] = type
    if len(test[1]) == 2:
        val = test[1][1]
        #if type in register_tables:
        #    if val in register_tables[type]:
        #        val = register_tables[type][val]
        # ^ handled in subexpr_fmt ?
        result['default'] = val

    result['modifiers'] = test[0]

    return result

modifiers = {'||': ('absolute', lambda x: Suppress('|') + x + Suppress('|')), '!': ('not', lambda x: Suppress('!') + x),
             '-': ('negate', lambda x: Suppress('-') + x), '~': ('invert', lambda x: Suppress('~') + x)}

quoted_expr = lambda c : Suppress("'") + c + Suppress("'")
pp_input_modifiers = ZeroOrMore(Suppress('[') + Or(modifiers.keys()) + Suppress(']')) #('||' | Literal('!') | Literal('~') | '-') + Suppress(']'))
pp_spec_assign = (Group(pp_input_modifiers) + Group(pp_spec_type) + Suppress(':') + pp_var_name).add_parse_action(parse_spec_assign)
pp_spec_variable0 = (quoted_expr('&') + pp_spec_assign + quoted_expr('=') + pp_spec_assign) | (quoted_expr('?') + pp_spec_assign) | pp_spec_assign
pp_spec_variable05 = OneOrMore((pp_spec_variable0 + Optional('+')) | '[' | ']' | Suppress('*'))
pp_spec_variable1 = OneOrMore((pp_spec_variable0 + Optional('+')) | '[' | ']' | Suppress('*'))
#pp_spec_variable1 = OneOrMore(pp_spec_variable05 | '[' + pp_spec_variable05 + ']' + Optional(Suppress('*')))
#pp_spec_variable1 = OneOrMore((pp_spec_variable0 | '[' + pp.delimited_list(pp_spec_variable0, '+' | White()) + ']' + Optional(Suppress('*'))))
pp_spec_variable2 = OneOrMore(pp_spec_variable1 | Suppress('{') + pp_spec_variable1 + Suppress('}'))
#  ^ I think the interpretation of {} is that the compiler can do these, so they are optional even with or without a default value? But of course they mustn't be overwritten if the auther explicitly gives values for them.
pp_spec_variable3 = pp_spec_variable2 | Suppress('$(') + pp_spec_variable2 + Suppress(')$')
pp_spec_variable = pp_spec_variable3 | Keyword('Opcode')

# ',' A:srcAttr[ UniformRegister:URa + SImm(11/0)*:URa_offset ]

#pp_spec_variable1 = ('[' + pp_spec_variable0 + ']') | ('{' + pp_spec_variable0 + '}') | ('$(' + pp_spec_variable0 + ')$') | ('$( {' + pp_spec_variable0 + '} )$') | pp_spec_variable0
#pp_spec_variable = pp_spec_variable0 | ('[' + pp_spec_variable0 + ']') | ('{' + pp_spec_variable0 + '}') | ('$(' + pp_spec_variable0 + ')$')

#pp_spec_pred = Suppress('PREDICATE') + '@' + pp_spec_variable#(Literal('UniformPredicate(UPT):UPg') | 'Predicate(PT):Pg')  # Just implement the only cases seen in the data for now.
pp_spec_modifier = Group('/' + pp_var_name + Suppress(Optional(QuotedString('(', endQuoteChar=')')) + ':') + pp_var_name)
#pp_spec_inputs = pp_spec_variable
#pp_format_spec = Optional(pp_spec_pred) + 'Opcode' + ZeroOrMore(pp_spec_modifier) + ZeroOrMore(pp_spec_inputs)

pp_class = Suppress(Literal('CLASS') | Literal('ALTERNATE CLASS')) + QuotedString('"')  # Suppress('"') + ... + Suppress('"')
# pp_format = Group(Literal('FORMAT') + ... + Suppress(';'))
pp_format_alias = Group(Literal('FORMAT_ALIAS') + ... + Suppress(';'))
pp_remap = Group(Literal('REMAP') + ... + Suppress(';'))

#$( RegisterFAU:Rd /optCC(noCC):writeCC )$
#',' $( [-] RegisterFAU:Ra {/REUSE(noreuse):reuse_src_a} )$
class SSuppress(Suppress):
    #@property
    #def name(self) -> str:
    def _generateDefaultName(self):
        return str(self.expr) #self.expr.name

class SOptional(Optional):
    def _generateDefaultName(self):
        return str(self.expr)

def parse_fmt(test):
    # FIXME: Instead of spookily editing the dict by reference.
    #  it would probably be better if parsing returned the Dict containing the modified (meaning non-default) entries
    variable_map = {}
    repeated_types = set()
    variable_map_alias = {}

    def subexpr_fmt(tok, add_to_var_map=True):
        type = tok['type']
        name = tok['name']

        if not type in repeated_types:
            if not type in variable_map_alias:
                variable_map_alias[type] = name
            else:
                del variable_map_alias[type]
                repeated_types.add(type)

        #def action(x):
            # print(type, x[0])
            # lambda x, type=str(type): register_tables[type][x[0]]
        #    return replace_with(register_tables[type][x[0]])

        if 'default' in tok and isinstance(tok['default'], Immediate):
            subexpr = tok['default'].token()
        else:
            subexpr = pp.Or(register_tables[type].keys()).set_parse_action(token_map(register_tables[type].__getitem__))  # # FIXME <- should be the set of possible values.


        subexpr.set_name(type)
        if tok['dotsep']:
            subexpr = Suppress('.') + subexpr
            subexpr.set_name('.' + type)

        if add_to_var_map:
            value = None
            if 'default' in tok:
                value = tok['default']  # <- An integer literal.
                if isinstance(value, tuple):
                    # print('wut', test, tok)
                    assert False
                    value = value[1]  # FIXME: Why

                if not isinstance(value, Immediate): #not isinstance(value, int):
                    value = register_tables[type][value]  # <- A reference to a register table value.
            # print(type, name, value)
            variable_map[name] = value
            # x[0] if isinstance(x[0], int) else register_tables[type][x[0]])
            #x[0] if isinstance(x[0], int) else register_tables[type][x[0]])
            #print(x[0]))
            # register_tables[type][x[0]]
            subexpr.add_parse_action(lambda x: (name, x if isinstance(x, int) else x[0]))
            # subexpr.set_parse_action(lambda x: (name, print(x)))
            # subexpr.add_parse_action(lambda x: (name, print(x)))
            # subexpr.add_parse_action(lambda x: variable_map.__setitem__(name, x[0]))

            for mod in tok['modifiers'][::-1]:  # <- note order/precedence is decided by the instruction format.
                modname = name + '@' + modifiers[mod][0]
                variable_map[modname] = int(False)
                prev_name = subexpr.name
                subexpr = (Empty().set_parse_action(lambda x: (modname, int(True))) + modifiers[mod][1](subexpr)) | subexpr
                subexpr.set_name('[' + mod + '] ' + prev_name)
                # ^ We attach the action to an empty token. Alternatively it could be attached to one of the tokens in
                #   the modifyer expresssion e.g. "!" in "!PT" - but as we see with |R4|

                # subexpr = modifiers[mod][1](subexpr).add_parse_action(lambda: variable_map.__setitem__(modname, int(True))) | subexpr
        return subexpr

    expr = Empty().set_name('')

    while test:
        # So bad
        tok = test.pop(0)
        # subexpr = Empty()
        if isinstance(tok, str):
            if tok == 'Opcode':
                pre_expr = expr
                pre_expr.set_name(pre_expr.name[1:-1].strip())
                expr = Empty().set_name('')
                continue
            subexpr = SSuppress(tok) if tok == '@' else SOptional(SSuppress(tok))
            if tok == ',':
                # ^ Let comma represent either whitespace or literal comma separation.
                subexpr = SSuppress(tok | White())
            subexpr.set_name(tok)
            # expr += subexpr
            if tok == '&':
                # E.g. for "& REQ = BITSET" we suppress all except BITSET
                s1 = test.pop(0)
                s2 = test.pop(0)
                piece = SSuppress(subexpr_fmt(s1, False) + SSuppress(s2).set_name(s2))
                piece.set_name(piece.name[1:-1])
                subexpr += piece
                # expr += piece
                #subexpr.set_name(s1 + ' ' + s2)
            if tok in '?@&':
                value = test.pop(0)
                # piece = subexpr_fmt(value)
                subexpr += subexpr_fmt(value)
                if 'default' in value and (not isinstance(value['default'], Immediate) or (value['default']._default is not None)):
                    #if isinstance(value['default'], Immediate):
                    #    print(value, value['default']._default)
                    # print(str(subexpr), repr(subexpr))
                    subexpr = Optional(subexpr)  # or subexpr
                else:
                    subexpr.set_name(subexpr.name[1:-1])
                # subexpr += piece

            expr += subexpr
        else:
            subexpr = subexpr_fmt(tok)
            if 'default' in tok and (not isinstance(tok['default'], Immediate) or (tok['default']._default is not None)):
                subexpr = Optional(subexpr)
            expr += subexpr
    #expr.set_name(expr.name[1:-1])
    #print(expr)
    #print(pre_expr)
    # print(len(variable_map.keys()))
    return variable_map, pre_expr, expr, variable_map_alias

pp_format_deep = Optional(Suppress('PREDICATE') + Literal('@')) + ZeroOrMore(Optional(quoted_expr(',')) + pp_spec_variable) + Suppress(';')
pp_format = Group(Literal('FORMAT') + pp_format_deep.set_parse_action(parse_fmt))

print(pp_spec_variable.parse_string("""C:Sb[UImm(5/0*):Sb_bank]*   [SImm(17)*:Sb_addr]""", parse_all=True))

test = """
    FORMAT PREDICATE @[!]Predicate(PT):Pg Opcode /Test:fcomp /FTZ(noFTZ):ftz /Bop:bopopt
             Predicate:Pd ',' Predicate:nPd
             ',' $( [-][||] RegisterFAU:Ra {/REUSE(noreuse):reuse_src_a} )$
             ',' F32Imm(64):uImm /UnaryNeg(noNEG):jneg /UnaryAbs(noABS):jabs
             ',' [!]Predicate:Pa
     $( { '&' REQ:req '=' BITSET(6/0x0000):req_sb_bitset } )$
     $( { '?' USCHED_INFO:usched_info } )$ ; 
"""



# print(pp_format.parse_string(test, parse_all=True))
# print(pp_format.parse_string(test, parse_all=True)[0][1])

if 0:
    a, b, c, _ = pp_format.parse_string(test, parse_all=False)[0][1]

    #b = SSuppress('Opcode')
    #b += c
    # b.set_name(b.name[-1:1])
    # c.set_name(c.name[1:-1])
    b = (b + SSuppress('Opcode')) + c
    # .replace('{ [', '{[')
    print(str(b).replace(' ,', ',').replace('{', '').replace('}', '').replace('  ', ' '))
    exit(0)
    print(len(a.keys()))
    print(b.parse_string("""Opcode.SF1.XOR P2, P3, R5 2.5, P5 ?W1G"""))
    #print(b.parse_string("""OpcodeR3, -P2, P3, R5 2.5"""))
    #print(dict(list(b.parse_string("""Opcode.FTZ R3, -R4, 5, R5 ?W1G"""))))
    print(a)
    print(len(a.keys()))
    exit(0)



pp_conditions = Group(('CONDITIONS' | Literal('CONDITION')) + Dict(ZeroOrMore(Group(pp_var_name + Group(Optional(White().suppress()) + SkipTo(Optional(White().suppress()) + ":" + LineEnd() + '"') + (Suppress(":" + LineEnd()) + QuotedString('"')))), stop_on="PROPERTIES"), asdict=True))

pp_class_list2 = lambda x, stop_on=None: Group(x + Dict(ZeroOrMore(Suppress(Keyword(x)) | Group(pp_var_name + ((Suppress('=') + ... + Suppress(';')) | Suppress(';')) ), stop_on=stop_on), asdict=True))
pp_list_encoding = lambda x, stop_on=None: x + Dict(ZeroOrMore(Group(Combine(delimited_list(Combine(Optional('!') + pp_var_name), ','), join_string=',') + Optional(Suppress('=') + Suppress(Optional('*')) + (INTEGER_parsed | SkipTo(';'))) + Suppress(';')), stop_on=stop_on), asdict=True)
# ^ Alternative, just add comma and ! to the pp_var_name Word used in the pattern (will be simpler, but also then requires more than a single argument change if the tokens are separated by space)

from collections import defaultdict
# TODO: place these parsers in a class, to avoid global variables.
opcodes_mnemonic = {}  # Many to one. 643 entries for sm_86
opcodes_reverse = defaultdict(set)  # One to many.
opcode_synonyms = {}  # One to one (by assertion contract in parse_opcodes).
def parse_opcodes(test):
    key = int(test[1], 2) if 'b' in test[1].lower() else int(test[1])
    assert(len(set(test[1::2])) == 1)  # Assert only one OPCODE is described
    # assert(key not in opcodes)  # Assert all instruction entries have unique opcodes <- fails

    opcodes_mnemonic[key] = test[-2]
    for syn in test[:-2:2]:
        assert not (syn in opcode_synonyms) or (opcode_synonyms[syn] == test[-2])  # Assert there is only the one synonym: syn in synonyms => synonyms[syn] == test[-2]
        opcode_synonyms[syn] = test[-2]
    opcodes_reverse[test[-2]].add(key)
    return key, test[::2]

bitfields_used = set()
opcode_bitpatterns = set()
# def parse_encodings(test):
#     for key, value in test[1].items():
#         if value == 'Opcode':
#             opcode_bitpatterns.add(key)
#         for subkey in key.split(','):
#             negated = subkey.startswith('!')
#             if negated: subkey = subkey[1:]
#             bitfields_used.add(subkey)
#     return test

pp_opcode = Group('OPCODES' + OneOrMore(pp_var_name + Suppress('=') + (INT_BINARY | INT_DECIMAL) + Suppress(';')).set_parse_action(parse_opcodes))
pp_body = Optional(pp_conditions) + Optional(pp_class_list2('PROPERTIES')) + Optional(pp_class_list2('PREDICATES')) + pp_opcode + Group(pp_list_encoding('ENCODING'))  #.set_parse_action(parse_encoding)
pp_instruction = pp_class + Dict(pp_format + Optional(pp_format_alias) + pp_body + Optional(pp_remap), asdict=True)

def parse_instruction(test):
    binary_opcode, opcodes = test[1]['OPCODES']
    # Add the opcode mnemonic to the format.
    variable_map, pre_expr, expr, variable_map_alias = test[1]['FORMAT']
    variable_lookup_alias = {b:a for a, b in variable_map_alias.items()}
    test[1]['variables'] = variable_map
    # test[1]['variables_alias'] =
    variable_map['Opcode'] = binary_opcode

    def parse_format_post(test):
        result = copy.deepcopy(variable_map)  # FIXME: Use deepcopy if Immediate is not immutable.
        result.update(dict(list(test)))
        result.update({variable_lookup_alias[a]:b for a, b in result.items() if a in variable_lookup_alias})
        #print('tosst', test, result)
        return result

    #opcode_expr = Or(opcodes).suppress()
    opcode_expr = Literal(opcodes[-1]).suppress()
    expr = pre_expr + opcode_expr + expr
    expr.add_parse_action(parse_format_post)

    test[1]['FORMAT'] = expr

    # NOTE: FIXME? We discarded the immediate field bitcount value in the instruction parsing.
    #              This is under the assumption that the bitfield size exactly matches this bitcount as well.
    #              This may be important w.r.t. the encoding of signed/unsigned integers as well (the signedness information was also discarded!)

    for key, value in test[1]['ENCODING'].items():
        if value == 'Opcode':
            opcode_bitpatterns.add(key)
            value = binary_opcode

        for subkey in key.split(','):
            negated = subkey.startswith('!')
            if negated: subkey = subkey[1:]
            bitfields_used.add(subkey)

    return test


pp_instruction.add_parse_action(parse_instruction)

if False:
    with open("test.txt", "r", encoding="ascii") as f:
        testdata = f.read()
    print(OneOrMore(Group(pp_instruction)).parse_string(testdata, parse_all=True))
    exit()

# pp_instruction = pp_class + pp_format + Optional(pp_alternative) + pp_conditions + pp_class_list('PROPERTIES') + pp_class_list('PREDICATES') + pp_class_list('OPCODES') + pp_encoding

#SkipTo('ENCODING')  + pp_class_list('ENCODING')
# atom_arrive__Ra32_popcinc

#parse_result = pp.OneOrMore(Group(pp_instruction)).parse_string('\n'.join(instructions.split("\n")[:300]),  parse_all=False)
# parse_result = OneOrMore(Group(pp_instruction)).parse_string(instructions,  parse_all=True)

parse_result = (pp_pre + Dict(ZeroOrMore(Group(pp_instruction)), asdict=True)).parse_string(data, parse_all=True)

#def nest_print(lst):
#    if ~isinstance(str, lst):
# atom__RaNonRZ

# print(json.dumps(parse_result[:100], cls=PyParseEncoder, sort_keys=False, indent=2))

architecture, instructions = parse_result

bitfield_invert_translation = str.maketrans('.X', 'X.')
bitfield_to_binary = str.maketrans('.X', '01')
bitfields = architecture['FUNIT']['BITFIELDS']
bitfmt = '{0:0'+architecture['FUNIT']['ENCODING WIDTH']+'b}'

#def encode(silhouette, encoding):
#    val_str = ('{0:0' + str(silhouette.count('1')) + 'b}').format(value)
#    return silhouette.replace('1', '{}').format(*val_str)

opcodes = {}



# variable_map, encoding
def instruction_encoder_factory(instruction):
    result = instruction['FORMAT'].copy()
    encoding = instruction['ENCODING']

    def encode(test):
        full_code = 0
        variable_map = test[0]
        for key, value in encoding.items():
            if key.startswith('!'):
                continue
            if isinstance(value, str) and ('SCALE' in value or 'MULTIPLY' in value):
                # Handle the case of SCALE, means the value is somehow fitted into a smaller field by some scaling
                # e.g. for "TEX" we have a 13-width bitfield: TidB = UImm(16)*:tid MULTIPLY 4 SCALE 4
                raise NotImplementedError("SCALE and MULTIPLY is not implemented yet")
            if isinstance(value, int):
                pass
            elif value in variable_map:
                value = variable_map[value].__index__()
            else:
                value_fun = value.partition('(')
                # TODO: Handle constbankaddress - maybe just custom implement it here?
                if value_fun[0] in architecture['TABLES']:
                    args = []
                    for arg in value_fun[2][:-1].split(','):
                        arg = arg.strip()  # Just in case
                        arg = variable_map[arg].__index__()
                        #if isinstance(arg, Immediate):
                        #    arg = arg.__index__()
                        args.append(str(arg))
                    args = ' '.join(args)
                    if args in architecture['TABLES'][value_fun[0]]:
                        value = architecture['TABLES'][value_fun[0]][args]
                    else:
                        print('Failed encoding arguments', args, 'for', value)
                elif value_fun[0].startswith('ConstBankAddress'):
                    args = []
                    for arg in value_fun[2][:-1].split(','):
                        arg = arg.strip()  # Just in case
                        arg = variable_map[arg]
                        if isinstance(arg, Immediate):
                            arg = arg.__index__()
                        args.append(arg)

                    #if value_fun[0][-1] == '2':
                        # ConstBankAddress2 for e.g. FADD
                        # A word turns out to be 4 bytes, meaning the last address is 0x4000 since 0x4000*4 = 65536 corresponds to 64 Kb of memory per bank.
                        #value = (args[0]<<14) + args[1]>>2
                        # This is also evident from the error condition: "Constant offsets must be aligned on a 4B boundary"
                    #elif value_fun[0][-1] == '0':
                        # ConstBankAddress0 for e.g. ULDC
                        # Word size is 1 byte in this case, this type of access is more granular.
                        # value = (args[0]<<16) + args[1]
                    shift = int(value_fun[0][-1])
                    assert (args[1] % (1<<shift)) == 0, f"Constant offsets must be aligned to {1<<shift}B"
                    # ^ Alternative formulation: args[1] & ((1<<shift)-1)
                    value = (args[0]<<(16-shift)) + args[1]>>shift

                    # TODO: ^ Sizes 14 and 16 should be inferred from the corresponding bitfields I guess.
                    # print('args for ConstBankAddress2', args)
                elif value_fun[0] == 'Identical':
                    # Not sure why Identical is a function. It just returns the value of the arguments, that must all match in value.
                    args = []
                    for arg in value_fun[2][:-1].split(','):
                        arg = arg.strip()  # Just in case
                        arg = variable_map[arg]
                        if isinstance(arg, Immediate):
                            arg = arg.__index__()
                        args.append(arg)
                    assert all([arg==args[0] for arg in args]), f"Arguments {value_fun[2][:-1].split(',')} must be identical in value."
                    value = args[0]
                else:
                    print('Failed encoding value:', value)

            # Now value should either be an int, or a Immediate value (which requires some special handling)
            silhouette = sum([int(bitfields[subkey].translate(bitfield_to_binary), 2) for subkey in key.split(',')])  # We assume comma-separated destinations are non-overlapping, so the union is equal to sum
            silhouette = bitfmt.format(silhouette)
            # print(silhouette)
            code = 0 # TODO: None
            if isinstance(value, Immediate):
                if not value._type.startswith('F'):
                    # Integer/bitfield case
                    if value._type[-4] == 'S':
                        # Signed case
                        value = value._default % (1 << value._width)
                    else:
                        value = value._default
                elif value._type.startswith('F32'):
                    # https://stackoverflow.com/a/16444786
                    value = struct.unpack('!i', struct.pack('!f', float(value._default)))[0]  # <- Not sure if endianness can cause problems here?

            if isinstance(value, int):
                cnt = silhouette.count('1')
                value = value % (1<<cnt)
                val_str = ('{0:0' + str(cnt) + 'b}').format(value)  # <- implicitly asserts that bit length matches expected length?
                # ^ what if field size does not match value size?
                code = int(silhouette.replace('1', '{}').format(*val_str), 2)
            full_code |= code
        return full_code
    result.add_parse_action(encode)

    return result

SASS_assembler = []

for inst_name, instruction in instructions.items():
#if True:
    #inst_name = 'ffma__RRR_RRR'
    #instruction = instructions[inst_name]

    encoding = instruction['ENCODING']
    encoding_archetype = 0
    encoding_silhouette = 0
    encoding_mask = 0
    encoding_asc = 0 #2**int(architecture['FUNIT']['ENCODING WIDTH'])-1
    binary_opcode = instruction['variables']['Opcode']  # / instruction['OPCODES'][0]
    binary_opcode_txt = None
    instruction['expr'] = instruction_encoder_factory(instruction)
    SASS_assembler.append(instruction['expr'])
    # print(bitfmt.format(instruction['expr'].parse_string('FFMA.FTZ R13, R31, R13, R36  ? W2', parse_all=True)[0]))
    # continue
    # instruction['expr'].parse_string('AL2P R4, R2, 5', parse_all=True)
    # {key:value for key, value in instruction['variables'].items() if isinstance(value)}
    continue
    handlers = []
    for key, value in encoding.items():
        opcode_field = value == 'Opcode'  # <- An exception, as this is more constant than variable...
        if opcode_field:
            # Replace value with the actual binary opcode.
            value = binary_opcode


        for subkey in key.split(','):
            negated = subkey.startswith('!')
            if negated:
                subkey = subkey[1:]
                assert value == ''
                # value = 0
            # Extract the corresponding bitfield
            bitfield = bitfields[subkey]
            #if negated:
            #    bitfield = bitfield.translate(bitfield_invert_translation)

            # Findings:
            # 1. Each bit is accounted for in the bitfield it seems - which may be why unused bits seem to have to be explicitly declared.
            # 2. The opcodes
            # TODO: Different ways to organize the bitfields. There are variable, const
            if negated:
                mask = bitfield.translate(bitfield_to_binary)
                mask = int(mask, 2)
                encoding_mask |= mask
                continue

            silhouette = bitfield.translate(bitfield_to_binary)
            if isinstance(value, int):
                val_str = ('{0:0' + str(silhouette.count('1')) + 'b}').format(value)  # <- implicitly asserts that bit length matches expected length?
                archetype = silhouette.replace('1', '{}').format(*val_str)
                if opcode_field:
                    binary_opcode_txt = archetype
                archetype = int(archetype, 2)
                silhouette = int(silhouette, 2)  # Convert from string to integral.

                assert (silhouette & encoding_silhouette) == 0  # <- Assert the bits are not already accounted for. (Fixed fields do not overlap. TODO: Generalize to verifying this property for general fields?)
                # ^ For newer architectures, the silhouette is simply equals to inverse of the corresponding "[...]__unused" bitfield.

                #if not negated:  # <- Are unused bits ignored or not? Should we include them in the set of "THESE BITS SHOULD BE ZERO TO ENCODE THIS INSTRUCTION"?
                encoding_silhouette |= silhouette
                # ^ Bitfield of fixed entries.
                encoding_archetype |= archetype  # <- same as encoding_archetype += archetype due to non-overlap.
                # ^ Bitfield of their values
            else:
                if opcode_field:
                    continue
                encoding_asc |= int(bitfield.translate(bitfield_to_binary), 2)
                # ^ Bitfield of variable entries.
                if value in instruction['variables']:
                    def handler(var_map, var=value):
                        val = var_map['value'][value]
                        if isinstance(val, Immediate):
                            val = val._default
                        pass
                    handlers.append(lambda var_map, var=value: var_map['value'][value])

                # print(value)
                # val_str = ('{0:0' + str(silhouette.count('1')) + 'b}').format(value)


    # assert not (archetype in opcodes)  # <- Assert uniqueness of opcodes - each instruction format has a corresponding opcode.

    # We put literal 0/1 for fixed fields, U for unused fields, and X for variable fields.
    # Maybe we could put this info in tables somehow, annotated by type and variable name?
    encoding_archetype_txt = ''.join([((a if s == '1' else ('X' if asc=='1' else 'Y')) if m=='0' else 'U') for a, m, s, asc in zip(bitfmt.format(encoding_archetype), bitfmt.format(encoding_mask), bitfmt.format(encoding_silhouette), bitfmt.format(encoding_asc))])

    encoding_key = encoding_archetype_txt
    # ^ Encoding keys are not unique -> One binary code may map to multiple SASS instructions, but any SASS instruction has only one binary encoding. (TODO: assuming instruction formats do not overlap - should we verify they all match disjoint sets of strings?)
    if False:
        if encoding_key in opcodes:
            other_inst_name, other_silhouette, other_archetype, other_mask, other_instruction = opcodes[encoding_key]
            union = other_silhouette & encoding_silhouette
            print('WAT', inst_name, other_inst_name)
            #print(bitfmt.format(encoding_archetype), '\n', encoding_archetype_txt, inst_name)
            #print(bitfmt.format(other_archetype), '\n', encoding_archetype_txt, other_inst_name)
            assert union == other_silhouette or union == encoding_silhouette  # Assert one is strictly a subset of the other (I hypothesize ALTERNATE CLASS means simply an alias with reduced functionality)
            if union == encoding_silhouette:
                opcodes[encoding_key] = inst_name, encoding_silhouette, encoding_archetype, encoding_mask, instruction
            # Now check if one instruction is strictly a subset of the other (in terms of bits used)
            # set(othr_instruction['variables'].keys())
            # print(archetype, inst_name, opcodes[archetype])
        else:
            opcodes[encoding_key] = inst_name, encoding_silhouette, encoding_archetype, encoding_mask, instruction

   #  print(encoding_archetype_txt, inst_name, bitfmt.format(encoding_archetype), bitfmt.format(encoding_mask), bitfmt.format(encoding_silhouette), bitfmt.format(encoding_asc))


assembler = ZeroOrMore(Or(SASS_assembler + [Suppress(QuotedString('/*', end_quote_char='*/'))]) + Suppress(Optional(';')) )
#print(parse_result)
# code[0] % (1<<64)  # & ((1<<64)-1)
# code[0] >> 64
def comment_remover(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " " # note: a space and not an empty string
        else:
            return s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)

# code = 'FADD.FTZ R2, -R2, c[0x0][0x18c];'
code = """
        /*0650*/                   UIADD3 UR9, UR9, -0x2, URZ ;
"""
binary_instructions = assembler.parse_string(code)
with open('test.dat', 'wb') as fout:
    sz = 64
    lower_64_bits = ((1 << sz) - 1)
    for binary in binary_instructions:
        fout.write(struct.pack('<QQ', binary & lower_64_bits, binary >> sz))
disasm = subprocess.run(['nvdisasm'] + '-c --print-raw --binary SM86 test.dat'.split(), text=True, capture_output=True).stdout
reasm = assembler.parse_string(disasm)

clean = lambda x: ';\n'.join(map(str.strip, comment_remover(x).split(';')))
print('Assembled:')
print(clean(code))
print('Corresponding disassembly of assembled code:')
# re.split('\n;')
disasm_cleaned = clean(disasm)
print(disasm_cleaned)
print(clean(code) == disasm_cleaned)

if list(reasm) != list(binary_instructions):
    # This error check should probably be removed, as reasm will not match in terms of control codes that are not visible in disasm?
    print('ReASM error! (The process of re-compiling the same code is not stable)')
    nonmatches = [i for i, (a, b) in enumerate(zip(reasm, binary_instructions)) if a != b]
    print('Reasm did not match disasm for instructions: ', nonmatches)
# nvdisasm -c --print-raw --binary SM86 test.dat
print(len(parse_result))
# print(opcodes)
print(len(opcodes))
print(opcode_synonyms)
print(opcodes_reverse)
print(opcodes_reverse.keys())


print(bitfields_used)
print([item for item in bitfields_used if not 'unused' in item])
# print(len(opcode_bitpatterns))

#print({value: key for key, value in parse_result[25].items() if "opcode" in key.lower()})
# print({value: key for key, value in bitfield.items() if "opcode" in key})

