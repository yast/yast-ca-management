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
# File:        include/ca-management/popup.ycp
# Package:     Configuration of CAs
# Summary:     Popup definitions
# Authors:     Stefan Schubert (schubi@suse.de)
#
# $Id$
module Yast
  module CaManagementPopupInclude
    def initialize_ca_management_popup(include_target)
      Yast.import "UI"
      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "Mode"
      Yast.import "Report"
      Yast.import "YaPI"
      Yast.import "YaPI::CaManagement"
      Yast.import "CommandLine"
    end

    # Popup to confirm after finish is pressed
    # @return `yes or `back
    def FinishPopup
      if Popup.ContinueCancelHeadline(
          # To translators: ContinueCancel Popup headline
          _("Finish"),
          # To translators: ContinueCancel Popup
          _("Really save configuration ?")
        )
        return :yes
      end
      :back
    end

    # Popup to confirm vhen exitting without saving
    # @return `exit or `back
    def ExitPopup
      if Popup.YesNoHeadline(
          # To translators: YesNo Popup headline
          _("Exit"),
          # To translators: YesNo Popup
          _("Really exit configuration without saving ?")
        )
        return :exit
      end
      :back
    end


    # Popup displaying openssl error messages
    # @return [void]
    def showErrorCaManagement
      messageMap = YaPI.Error
      message = Ops.get_string(messageMap, "summary", "")
      description = Ops.get_string(messageMap, "description", "")
      if Ops.greater_than(Builtins.size(message), 0)
        Builtins.y2error("Showing error: %1", messageMap)
        if CommandLine.StartGUI
          if Ops.greater_than(Builtins.size(description), 0) &&
            !Mode.autoinst # Just show a report if we are using AutoYaST (bnc#962328)
            if !Popup.AnyQuestion(
                Label.ErrorMsg,
                message,
                Label.OKButton,
                _("Details"),
                :focus
              )
              UI.OpenDialog(
                Opt(:decorated),
                HBox(
                  VSpacing(16),
                  VBox(
                    HSpacing(100),
                    # popup window header
                    Heading(message),
                    VSpacing(0.5),
                    RichText(Opt(:plainText), description),
                    VSpacing(1.5),
                    # push button label
                    PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton)
                  )
                )
              )

              UI.SetFocus(Id(:ok))
              UI.UserInput
              UI.CloseDialog
            end
          else
            Report.Error(message)
          end
        else
          # output to tty
          CommandLine.Print(message)
        end
      end
      nil
    end
  end
end
