import ida_kernwin
import ida_idaapi

try:
    from PyQt5 import QtWidgets
except ImportError:
    from PySide2 import QtWidgets


def copy_to_clipboard(text):
    QtWidgets.QApplication.clipboard().setText(text)


class CopyEA_Handler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        copy_to_clipboard("0x%X" % ea)
        ida_kernwin.msg("Copied address: 0x%X\n" % ea)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class CopyEA_Plugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Copy current address to clipboard"
    help = "Copy current address to clipboard"
    wanted_name = "Copy EA"
    wanted_hotkey = "Shift-Alt-C"

    def init(self):
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        ea = ida_kernwin.get_screen_ea()
        copy_to_clipboard("0x%X" % ea)
        ida_kernwin.msg("Copied address: 0x%X\n" % ea)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return CopyEA_Plugin()