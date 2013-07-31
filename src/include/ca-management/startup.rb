# encoding: utf-8

# ***************************************************************************
#
# Copyright (c) 2004 - 2012 Novell, Inc.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail,
# you may find current contact information at www.novell.com
#
# ***************************************************************************
#
# File:
#   startup.ycp
#
# Module:
#   CA Management
#
# Summary:
#   Shows all available Root CAs
#
# Authors:
#   Stefan Schubert <schubi@suse.de>
#
# $Id$
#
# CA Management - Root CAs
#
module Yast
  module CaManagementStartupInclude
    def initialize_ca_management_startup(include_target)
      Yast.import "UI"

      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/util.rb"

      @CAList = [] # CA list tree
    end

    # Creates CA items
    # @param [String] subCA - name ob the sub CA or empty if root
    # @return a list of CA items of the sub CA, formated for a UI tree
    def getCAList(subCA)
      result = []

      if Ops.less_or_equal(Builtins.size(subCA), 0)
        @CAList = YaPI::CaManagement.ReadCATree
        Builtins.y2milestone("Output of ReadCATree: %1", @CAList)
        if @CAList == nil
          showErrorCaManagement
          return deep_copy(result)
        end
      end
      Builtins.foreach(@CAList) do |elementList|
        if Ops.get_string(elementList, 1, "") == subCA
          subCA2 = getCAList(Ops.get_string(elementList, 0, ""))
          if Ops.greater_than(Builtins.size(subCA2), 0)
            result = Builtins.add(
              result,
              Item(
                Id(Ops.get_string(elementList, 0, "")),
                Ops.get_string(elementList, 0, ""),
                true,
                subCA2
              )
            )
          else
            result = Builtins.add(
              result,
              Item(
                Id(Ops.get_string(elementList, 0, "")),
                Ops.get_string(elementList, 0, "")
              )
            )
          end
        end
      end

      deep_copy(result)
    end

    # Deleting current CA
    def deleteCurrentCA
      Builtins.y2milestone("deleting CA: %1", CaMgm.currentCA)

      message = Builtins.sformat(_("Really delete CA %1?"), CaMgm.currentCA)

      if Popup.YesNoHeadline(_("Delete"), message) &&
          getPassword(CaMgm.currentCA) != nil
        if YaPI::CaManagement.DeleteCA(
            {
              "caName"   => CaMgm.currentCA,
              "caPasswd" => getPassword(CaMgm.currentCA)
            }
          ) == nil
          messageMap = YaPI.Error
          if Ops.get_string(messageMap, "code", "") == "CA_STILL_IN_USE"
            if Popup.YesNoHeadline(
                _("Force Delete"),
                _("This CA is still in use. Delete it?")
              )
              if YaPI::CaManagement.DeleteCA(
                  {
                    "caName"   => CaMgm.currentCA,
                    "caPasswd" => getPassword(CaMgm.currentCA),
                    "force"    => "1"
                  }
                ) == nil
                showErrorCaManagement
              end
            end
          else
            showErrorCaManagement
          end
        end
      end

      nil
    end


    # startup dialog
    # @return `finish, `enter, 'createRoot
    def Startup
      # help text 1/3
      helptext = _("<p>Select one CA and press <b>Enter CA</b>.</p>")
      # help text 2/3
      helptext = Ops.add(
        helptext,
        _(
          "<p><b>Create Root CA</b> generates a new root certificate authority.</p>"
        )
      )
      # help text 3/3
      helptext = Ops.add(
        helptext,
        _(
          "<p>For more information about CA Management, please read the manual.</p>"
        )
      )

      termList = getCAList("")

      buttons = VBox()
      # To translators: pushbutton label
      buttons = Builtins.add(
        buttons,
        HBox(HWeight(1, PushButton(Id(:enter), Opt(:key_F4), _("&Enter CA"))))
      )
      buttons = Builtins.add(
        buttons,
        HBox(HWeight(1, PushButton(Id(:delete), Opt(:key_F5), _("&Delete CA"))))
      )
      buttons = Builtins.add(buttons, VStretch())
      # To translators: pushbutton label
      buttons = Builtins.add(
        buttons,
        HBox(
          HWeight(
            1,
            PushButton(Id(:createRoot), Opt(:key_F3), _("&Create Root CA"))
          )
        )
      )
      # To translators: pushbutton label
      buttons = Builtins.add(
        buttons,
        HBox(HWeight(1, PushButton(Id(:import), _("&Import CA"))))
      )

      contents = HBox()
      contents = Builtins.add(
        contents,
        HWeight(
          9,
          Tree(
            Id(:tree),
            Opt(:notify, :vstretch),
            # To translators: tree headers
            _("CA Tree"),
            termList
          )
        )
      )
      contents = Builtins.add(contents, HWeight(4, buttons))


      # To translators: dialog label
      Wizard.SetContents(_("CA Selection"), contents, helptext, false, true)
      Wizard.SetNextButton(:next, Label.FinishButton)
      UI.ChangeWidget(Id(:abort), :Enabled, false)

      firstEntry = Ops.get(@CAList, 0) { ["", ""] }
      CaMgm.currentCA = Ops.get(firstEntry, 0, "")

      UI.ChangeWidget(Id(:tree), :CurrentItem, CaMgm.currentCA)

      ui = nil
      begin
        anyitems = UI.QueryWidget(Id(:tree), :CurrentItem) != nil
        UI.ChangeWidget(Id(:enter), :Enabled, anyitems)
        UI.ChangeWidget(Id(:delete), :Enabled, anyitems)

        ui = Convert.to_symbol(UI.UserInput)
        if Builtins.contains([:enter, :delete], ui) && anyitems
          CaMgm.currentCA = Convert.to_string(
            UI.QueryWidget(Id(:tree), :CurrentItem)
          )
          if ui == :enter
            # checking password
            ui = :again if getPassword(CaMgm.currentCA) == nil
          end
          deleteCurrentCA if ui == :delete
        end
        importCAFromDisk if ui == :import
      end until Builtins.contains(
        [:createRoot, :enter, :next, :import, :delete, :cancel],
        ui
      )

      ui
    end
  end
end
