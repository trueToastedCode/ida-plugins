import ida_kernwin
import ida_idaapi
import ida_funcs
import ea_tools_common as common


class CopyBlocks_Handler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)

        if not func:
            ida_kernwin.msg("No function at current address.\n")
            return 1

        fname = common.get_func_name(func.start_ea)

        header = []
        header.append("; " + "=" * 50)
        header.append("; Function @ 0x%X (%s) [TOP LEVEL]" % (func.start_ea, fname))
        header.append("; Call path: %s" % fname)
        header.append("; " + "=" * 50)

        body_lines = common.get_function_flat_lines(func, start_ea=ea)

        output_text = "\n".join(header) + "\n" + "\n".join(body_lines)

        path = common.save_text_to_file(output_text, "Save flat block dump as")
        if not path:
            ida_kernwin.msg("Save cancelled.\n")
            return 1

        ida_kernwin.msg("Saved flat dump to %s\n" % path)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class CopyBlocks_Plugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Dump reachable basic blocks (flat, single function) to a text file"
    help = "Dump reachable basic blocks (flat, single function) to a text file"
    wanted_name = "Copy Blocks"
    wanted_hotkey = "Ctrl-Alt-B"

    def init(self):
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        CopyBlocks_Handler().activate(None)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return CopyBlocks_Plugin()