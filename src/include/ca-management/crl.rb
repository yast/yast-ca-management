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
#   crl.ycp
#
# Module:
#   CA Management
#
# Summary:
#
#
# Authors:
#   Stefan Schubert <schubi@suse.de>
#
# $Id$
#
# CRL of a selected CA
#
module Yast
  module CaManagementCrlInclude
    def initialize_ca_management_crl(include_target)
      Yast.import "UI"
      textdomain "ca-management"

      Yast.import "Label"
      Yast.import "CaMgm"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/crlDefault.rb"
      Yast.include include_target, "ca-management/crlExport.rb"

      # help text 1/4
      @CRLHelptext = _("<p>Here, see the most important values of the CRL.</p>")
      # help text 2/4
      @CRLHelptext = Ops.add(
        @CRLHelptext,
        _("<p>With <b>Generate CRL</b>, a new CRL will be generated.</p>")
      )
      # help text 3/4
      @CRLHelptext = Ops.add(
        @CRLHelptext,
        _("<p><b>View</b> shows a complete description.</p>")
      )
      # help text 4/4
      @CRLHelptext = Ops.add(
        @CRLHelptext,
        _("<p>You can <b>Export</b> the CRL to a file or LDAP Directory.</p>")
      )
    end

    # createCRL -  creating new CRL
    # @param CA name
    # @return `again

    def createCRL(_CAname)
      ret = YaPI::CaManagement.ReadCRLDefaults(
        { "caName" => _CAname, "caPasswd" => getPassword(_CAname) }
      )
      Builtins.y2milestone(
        "ReadCRLDefaults(%1) return %2",
        { "caName" => _CAname },
        ret
      )

      # asking user
      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(2),
          VBox(
            VSpacing(1),
            # popup window header
            Heading(_("Generate New CRL")),
            VSpacing(1),
            IntField(
              Id(:entry),
              _("&Valid to (days):"),
              1,
              10000,
              Builtins.tointeger(Ops.get_string(ret, "days", "30"))
            ),
            VSpacing(1),
            HBox(
              PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
              HStretch(),
              PushButton(Id(:cancel), Opt(:key_F9), Label.AbortButton)
            ), # push button label
            VSpacing(1)
          ),
          HSpacing(2)
        )
      )

      UI.SetFocus(Id(:entry))
      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)
        days = Convert.to_integer(UI.QueryWidget(Id(:entry), :Value))
        if ui == :ok
          # generating CRL
          ret2 = nil
          ret2 = YaPI::CaManagement.AddCRL(
            {
              "caName"   => _CAname,
              "caPasswd" => getPassword(CaMgm.currentCA),
              "days"     => Builtins.tostring(days)
            }
          )
          showErrorCaManagement if ret2 == nil || ret2 == false
        end
      end until Builtins.contains([:ok, :cancel], ui)
      UI.CloseDialog

      :again
    end


    # showLongCRLDescription - description of a CRL in textform
    # @param CA name
    def showLongCRLDescription(_CAname)
      ret = Convert.to_string(
        YaPI::CaManagement.ReadCRL(
          {
            "caName"   => _CAname,
            "caPasswd" => getPassword(_CAname),
            "type"     => "plain"
          }
        )
      )

      Builtins.y2milestone("ReadCRL(%1): %3", _CAname, ret)
      ret = Ops.add(Ops.add("<pre>", ret), "</pre>")

      if ret == nil
        showErrorCaManagement
      else
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

    # getDescription - CRL description
    # @param CA name
    # @return a string with the CRL description
    def getCRLDescription(_CAname)
      ret = Convert.to_map(
        YaPI::CaManagement.ReadCRL(
          {
            "caName"   => _CAname,
            "caPasswd" => getPassword(_CAname),
            "type"     => "parsed"
          }
        )
      )
      if ret == nil
        messageMap = YaPI.Error
        message = Ops.get_string(messageMap, "summary", "")
        description = Ops.get_string(messageMap, "description", "")
        if Ops.greater_than(Builtins.size(message), 0)
          retString = "\n"
          retString = Ops.add(Ops.add(retString, message), "\n")
          retString = Ops.add(retString, description)
          return retString
        end
      end
      Builtins.y2milestone("ReadCRL(%1): %2", _CAname, ret)

      text = _("<p><b>Certificate Revocation List (CRL):</b></p>")
      text = Ops.add(text, "<pre>")
      text = Ops.add(
        Ops.add(text, "\nVersion: "),
        Ops.get_string(ret, "VERSION", "")
      )
      text = Ops.add(
        Ops.add(text, "\nSignature Algorithmus: "),
        Ops.get_string(ret, "SIGNATURE_ALGORITHM", "")
      )
      text = Ops.add(
        Ops.add(text, "\nIssuer: "),
        Ops.get_string(ret, "ISSUER", "")
      )
      text = Ops.add(
        Ops.add(text, _("\n\nLast Update: ")),
        Ops.get_string(ret, "LASTUPDATE", "")
      )
      text = Ops.add(
        Ops.add(text, _("\nNext Update: ")),
        Ops.get_string(ret, "NEXTUPDATE", "")
      )
      counter = 0
      Builtins.foreach(Ops.get_list(ret, "REVOKED_PARSED", [])) do |element|
        text = Ops.add(text, _("\n\nRevoked Certificates: ")) if counter == 0
        counter = Ops.add(counter, 1)
        reason = Ops.get_string(element, "REASON", "")
        reason = Builtins.deletechars(reason, "\n")
        text = Ops.add(
          Ops.add(text, "\n     Serial Number: "),
          Ops.get_string(element, "SERIAL", "")
        )
        text = Ops.add(
          Ops.add(text, "\n            Date:   "),
          Ops.get_string(element, "DATE", "")
        )
        text = Ops.add(Ops.add(text, "\n            Reason: "), reason)
      end

      text
    end

    # Dialog Tab - CRL -
    # @return [Yast::Term] for the CRL of a selected CA
    def getCRLTab
      contents = VBox(
        VSpacing(1),
        HBox(HSpacing(1), RichText(Id(:textinfo), ""), HSpacing(1)),
        HBox(
          HSpacing(1),
          PushButton(Id(:gererateCRL), _("&Generate CRL")),
          PushButton(Id(:view), _("&View")),
          PushButton(Id(:defaults), _("&Default")),
          HStretch(),
          # Fate (#2613)
          PushButton(Id(:exportDialog), _("Export")),
          #`MenuButton (_("Export"),
          #   [
          #    `item(`id(`exportFile), _("to &File") ),
          #    `item(`id(`exportLDAP), _("to &LDAP"))
          #    ]
          #   ),
          HSpacing(1)
        )
      )
      deep_copy(contents)
    end

    # Initialize the tab of the dialog
    def initCRLTab
      UI.ChangeWidget(Id(:textinfo), :Value, getCRLDescription(CaMgm.currentCA))

      nil
    end


    # Handle events in a tab of a dialog
    def handleCRLTab(event)
      event = deep_copy(event)
      ui = Ops.get(event, "ID")
      if ui == :gererateCRL
        createCRL(CaMgm.currentCA)
        ui = :again
      end
      showLongCRLDescription(CaMgm.currentCA) if ui == :view
      #	if (ui == `exportLDAP)
      #	{
      #	    exportToLDAP ("CRL", CaMgm::currentCA, "" ,"", "", "");
      #	}
      #	if (ui == `exportFile)
      #	{
      #	    exportCRLtoFile (CaMgm::currentCA);
      #	}
      exportCRL(CaMgm.currentCA) if ui == :exportDialog # (Fate #2613)
      editCRLDefaults(CaMgm.currentCA) if ui == :defaults
      Convert.to_symbol(ui)
    end
  end
end
