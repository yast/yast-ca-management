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
  module CaManagementDialogCaInclude
    def initialize_ca_management_dialog_ca(include_target)
      textdomain "ca-management"
      Yast.import "CaMgm"
      Yast.import "Label"
      Yast.import "Wizard"
      Yast.import "Popup"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/util.rb"
      Yast.include include_target, "ca-management/new_cert.rb"
      Yast.include include_target, "ca-management/ca.rb"
      Yast.include include_target, "ca-management/certificate.rb"
      Yast.include include_target, "ca-management/crl.rb"
      Yast.include include_target, "ca-management/request.rb"
    end

    # Faking Tab Widget for NCurses
    def DumbTabs(items, contents)
      items = deep_copy(items)
      contents = deep_copy(contents)
      tabs = HBox()

      Builtins.foreach(items) do |item|
        text = Ops.get_string(item, 1, "")
        idTerm = Ops.get_term(item, 0) { Id(:unknown) }
        tabs = Builtins.add(tabs, PushButton(idTerm, text))
      end

      tabs = Builtins.add(tabs, HStretch())

      Builtins.y2milestone("Creating tabs: %1", tabs)

      VBox(tabs, Frame("", contents))
    end


    # Dialog Zone Editor - Tab
    # @param [String] tab_id
    # @return [Yast::Term] dialog for ZoneEditorDialog()
    def getDialogCATab(tab_id)
      if tab_id == "CA"
        return getCATab
      elsif tab_id == "Certificates"
        return getCertificateTab
      elsif tab_id == "CRL"
        return getCRLTab
      elsif tab_id == "Request"
        return getRequestTab
      end
      # This should never happen, but ...
      Builtins.y2error("unknown tab_id: %1", tab_id)
      # When no dialog defined for this tab (software error)
      Label(_("Software error - Unknown Tab"))
    end

    def initDialogCATab(dialog)
      if dialog == "CA"
        initCATab
      elsif dialog == "Certificates"
        initCertificateTab
      elsif dialog == "CRL"
        initCRLTab
      elsif dialog == "Request"
        initRequestTab
      end

      nil
    end

    def getHelpText(dialog)
      if dialog == "CA"
        return @CAHelptext
      elsif dialog == "Certificates"
        return @certificateHelptext
      elsif dialog == "CRL"
        return @CRLHelptext
      elsif dialog == "Request"
        return @requestHelptext
      end
      "missing help text"
    end

    def storeDialogCATab(dialog)
      Builtins.y2debug("stroring current Tab")

      nil
    end

    def handleDialogCATab(dialog, event)
      event = deep_copy(event)
      ret = nil
      if dialog == "CA"
        ret = handleCATab(event)
      elsif dialog == "Certificates"
        ret = handleCertificateTab(event)
      elsif dialog == "CRL"
        ret = handleCRLTab(event)
      elsif dialog == "Request"
        ret = handleRequestTab(event)
      end
      ret
    end

    # Dialog CA - Main
    # @return [Object] dialog result for wizard
    def runCADialog
      # Dialog Caption - Expert Settings - Zone Editor
      caption = _("Certificate Authority (CA)")

      current_tab = "CA"

      tab_terms = [
        # Menu Item - CA - Tab
        Item(Id("CA"), _("&Description")),
        # Menu Item - CA - Tab
        Item(Id("Certificates"), _("C&ertificates")),
        # Menu Item - CA - Tab
        Item(Id("CRL"), _("CR&L")),
        # Menu Item - CA - Tab
        Item(Id("Request"), _("&Requests"))
      ]

      contents = VBox(
        Opt(:hvstretch),
        Left(Heading(Ops.add(_("CA Name: "), CaMgm.currentCA))),
        # Here start Tabs
        # FIXME: after `Tab implementation
        UI.HasSpecialWidget(:DumbTab) ?
          DumbTab(
            Id(:dumbtab),
            tab_terms,
            ReplacePoint(Id(:tabContents), getDialogCATab(current_tab))
          ) :
          DumbTabs(
            tab_terms,
            ReplacePoint(Id(:tabContents), getDialogCATab(current_tab))
          )
      )

      # FIXME: Only one help is used for all tabs. Maybe would be better to change the help for every single tab.
      Wizard.SetContentsButtons(
        caption,
        contents,
        getHelpText(current_tab),
        Label.BackButton,
        Label.OKButton
      )
      initDialogCATab(current_tab)

      event = nil
      ret = nil
      while true
        event = UI.WaitForEvent
        ret = Ops.get(event, "ID")

        break if ret == :next
        if ret == :back
          break
        elsif ret == :cancel || ret == :abort
          if Popup.ReallyAbort(true)
            return :abort
          else
            next
          end
        elsif ret == "CA" || ret == "Certificates" || ret == "CRL" ||
            ret == "Request"
          storeDialogCATab(current_tab)
          current_tab = Convert.to_string(ret)

          UI.ReplaceWidget(:tabContents, getDialogCATab(current_tab))
          Wizard.RestoreHelp(getHelpText(current_tab))
          initDialogCATab(current_tab)
        else
          # ensure the same tab selected
          if UI.HasSpecialWidget(:DumbTab)
            UI.ChangeWidget(Id(:dumbtab), :CurrentItem, current_tab)
          end
          ret = handleDialogCATab(current_tab, event)
          if ret == :again
            UI.ReplaceWidget(:tabContents, getDialogCATab(current_tab))
            Wizard.RestoreHelp(getHelpText(current_tab))
            initDialogCATab(current_tab)
          end
        end
      end

      storeDialogCATab(current_tab) if ret == :next

      Convert.to_symbol(ret)
    end
  end
end
