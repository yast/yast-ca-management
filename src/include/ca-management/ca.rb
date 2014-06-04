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
# File:        clients/ca_mgm.ycp
# Package:     CA Management
# Summary:     Main file
# Authors:     Stefan Schubert <schubi@suse.de>
#
# $Id$
#
# Main file for CA Management. Uses all other files.
module Yast
  module CaManagementCaInclude
    def initialize_ca_management_ca(include_target)
      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/crlDefault.rb"
      Yast.include include_target, "ca-management/certDefault.rb"

      @defaultSequence = {
        "ws_start"     => "new_default1",
        "new_default1" => {
          :next  => "new_default2",
          :again => "new_default1",
          :abort => :abort
        },
        "new_default2" => {
          :next  => "new_default3",
          :again => "new_default2",
          :abort => :abort,
          :back  => "new_default1"
        },
        "new_default3" => {
          :next  => :abort,
          :abort => :abort,
          :back  => "new_default2"
        }
      }

      # help text 1/2
      @CAHelptext = _("<p>Here, see the most important values of the CA.</p>")
      # help text 2/2
      @CAHelptext = Ops.add(
        @CAHelptext,
        _(
          "<p>Special information about the current CA is provided by <b>Certificates</b>, <b>CRL</b>, and <b>Advanced</b>.</p>"
        )
      )
    end

    # Creating new Client Certificate sequence
    # @return sequence result
    def newSubCASequence
      aliases = {
        "new_certinit"      => lambda { new_cert_init("Sub CA") },
        "new_certSaveDef"   => lambda { new_cert_save_default },
        "new_cert1"         => lambda { new_cert1("Sub CA") },
        "new_cert2"         => lambda { new_cert2("Sub CA") },
        "new_cert3"         => lambda { new_cert3("Sub CA") },
        "new_cert_advanced" => lambda { new_cert_advanced(false, "Sub CA") }
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ca_mgm")
      ret = WizardSequencer(aliases, CaMgm.certificateSequence)

      UI.CloseDialog

      ret
    end

    # Editing certificate defaults
    # @return sequence result
    def editDefaultSequence
      aliases = {
        "new_default1" => lambda { edit_default1 },
        "new_default2" => lambda { new_cert_advanced(true, "Default") },
        "new_default3" => lambda { edit_default2 }
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ca_mgm")
      ret = WizardSequencer(aliases, @defaultSequence)

      UI.CloseDialog

      ret
    end


    # showLongDescriptionCA - description of a CA in textform
    # @param CA name
    def showLongDescriptionCA(_CAname)
      ret = Convert.to_string(
        YaPI::CaManagement.ReadCA(
          {
            "caName"   => _CAname,
            "caPasswd" => getPassword(_CAname),
            "type"     => "plain"
          }
        )
      )
      Builtins.y2milestone("ReadCA(%1): %2", _CAname, ret)

      if ret == nil
        showErrorCaManagement
      else
        ret = Ops.add(Ops.add("<pre>", ret), "</pre>")
        UI.OpenDialog(
          Opt(:decorated),
          HBox(
            VSpacing(16),
            VBox(
              HSpacing(100),
              # popup window header
              Heading(_("Description")),
              VSpacing(0.5),
              RichText(ret),
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

      nil
    end


    # getDescriptionCA - description of a CA
    # @param CA name
    # @return a string with the CA description
    def getDescriptionCA(_CAname)
      text = Builtins.sformat(_("<p><b> Description for %1 </b></p>"), _CAname)

      ret = Convert.to_map(
        YaPI::CaManagement.ReadCA(
          {
            "caName"   => _CAname,
            "caPasswd" => getPassword(_CAname),
            "type"     => "parsed"
          }
        )
      )
      if ret == nil
        showErrorCaManagement
        return _("\nCA not found")
      end
      Builtins.y2milestone("ReadCA(%1): %2", _CAname, ret)

      dn = Ops.get_map(ret, "DN_HASH", {})
      if Ops.greater_than(Builtins.size(dn), 0)
        text = Ops.add(text, _("<p><b>Issued For:</b></p>"))
        text = Ops.add(text, "<pre>")
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nCommon Name:  ")),
          Ops.get_string(Ops.get_list(dn, "CN", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nOrganization: ")),
          Ops.get_string(Ops.get_list(dn, "O", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nLocation:     ")),
          Ops.get_string(Ops.get_list(dn, "L", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nState:        ")),
          Ops.get_string(Ops.get_list(dn, "ST", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nCountry:      ")),
          Ops.get_string(Ops.get_list(dn, "C", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nEMAIL:        ")),
          Ops.get_string(Ops.get_list(dn, "emailAddress", []), 0, "")
        )
        text = Ops.add(text, "</pre>")
      end

      issuer = Ops.get_map(ret, "ISSUER_HASH", {})
      if Ops.greater_than(Builtins.size(issuer), 0)
        text = Ops.add(text, _("<p><b>Issued By:</b></p>"))
        text = Ops.add(text, "<pre>")
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nCommon Name:  ")),
          Ops.get_string(Ops.get_list(issuer, "CN", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nOrganization: ")),
          Ops.get_string(Ops.get_list(issuer, "O", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nLocation:     ")),
          Ops.get_string(Ops.get_list(issuer, "L", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nState:        ")),
          Ops.get_string(Ops.get_list(issuer, "ST", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nCountry:      ")),
          Ops.get_string(Ops.get_list(issuer, "C", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nEMAIL:        ")),
          Ops.get_string(Ops.get_list(issuer, "emailAddress", []), 0, "")
        )
        text = Ops.add(text, "</pre>")
      end

      text = Ops.add(
        Ops.add(text, _("\nValid from: ")),
        Ops.get_string(ret, "NOTBEFORE", "")
      )
      text = Ops.add(
        Ops.add(Ops.add(text, "<br>"), _("\nValid to: ")),
        Ops.get_string(ret, "NOTAFTER", "")
      )
      text = Ops.add(
        Ops.add(Ops.add(text, "<br>"), "Fingerprint: "),
        Ops.get_string(ret, "FINGERPRINT", "")
      )

      text
    end


    # Dialog Tab - CA -
    # @return [Yast::Term] the selected CA
    def getCATab
      contents = VBox(
        VSpacing(1),
        HBox(HSpacing(1), RichText(Id(:textinfo), ""), HSpacing(1)),
        HBox(
          HSpacing(1),
          # To translators: pushbutton label
          Right(
            MenuButton(
              _("&Advanced..."),
              [
                Item(Id(:information), _("&View")),
                Item(Id(:cacpw), _("&Change CA Password")),
                Item(Id(:createSubCA), _("C&reate SubCA")),
                Item(Id(:exportFile), _("Export to &File")),
                Item(Id(:exportLDAP), _("Export to &LDAP")),
                Item(Id(:editDefault), _("&Edit Default"))
              ]
            )
          ),
          HSpacing(1)
        ),
        VSpacing(1)
      )
      deep_copy(contents)
    end

    # Initialize the tab of the dialog
    def initCATab
      UI.ChangeWidget(Id(:textinfo), :Value, getDescriptionCA(CaMgm.currentCA))

      nil
    end

    # Handle events in a tab of a dialog
    def handleCATab(event)
      event = deep_copy(event)
      ret = Ops.get(event, "ID")
      showLongDescriptionCA(CaMgm.currentCA) if ret == :information
      changePassword(CaMgm.currentCA, "") if ret == :cacpw
      exportToLDAP("CA", CaMgm.currentCA, "", "", "", "") if ret == :exportLDAP
      exportCAtoFile(CaMgm.currentCA) if ret == :exportFile
      if ret == :editDefault
        # initialize global variable
        CaMgm.initializeDefault = true
        CaMgm.currentDefault = "Sub CA"
        editDefaultSequence
      end
      newSubCASequence if ret == :createSubCA
      nil
    end
  end
end
