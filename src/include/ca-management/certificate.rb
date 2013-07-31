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
  module CaManagementCertificateInclude
    def initialize_ca_management_certificate(include_target)
      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "YaPI::CaManagement"

      @certificateID = []

      # help text 1/6
      @certificateHelptext = _(
        "<p>First, see a list view with all available certificates from this CA. The columns are the DN of the certificates including the e-mail address and the state of the certificate (such as valid or revoked).</p>"
      )
      # help text 2/6
      @certificateHelptext = Ops.add(
        @certificateHelptext,
        _("<p>Select one of the certificates and execute some actions.</p>")
      )
      # help text 3/6
      @certificateHelptext = Ops.add(
        @certificateHelptext,
        _(
          "<p><b>View</b> opens a window with a text representation of the complete certificate.</p>"
        )
      )
      # help text 4/6
      @certificateHelptext = Ops.add(
        @certificateHelptext,
        _(
          "<p>Furthermore, you can <b>Revoke</b>, <b>Delete</b>, or <b>Export</b> a certificate.</p>"
        )
      )
      # help text 5/6
      @certificateHelptext = Ops.add(
        @certificateHelptext,
        _(
          "<p>With <b>Add</b>, generate a new server or client certificate.</p>"
        )
      )
      # help text 6/6
      @certificateHelptext = Ops.add(
        @certificateHelptext,
        _(
          "<p>In the area below, see the most important values of the selected certificate.</p>"
        )
      )

      @currentSubjectAltName = ""
    end

    # Creating new Server Certificate sequence
    # @return sequence result
    def newServerCertificateSequence
      aliases = {
        "new_certinit"      => lambda { new_cert_init("Server Certificate") },
        "new_certSaveDef"   => lambda { new_cert_save_default },
        "new_cert1"         => lambda { new_cert1("Server Certificate") },
        "new_cert2"         => lambda { new_cert2("Server Certificate") },
        "new_cert3"         => lambda { new_cert3("Server Certificate") },
        "new_cert_advanced" => lambda do
          new_cert_advanced(false, "Server Certificate")
        end
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ca_mgm")
      ret = WizardSequencer(aliases, CaMgm.certificateSequence)

      UI.CloseDialog

      ret
    end

    # Creating new Client Certificate sequence
    # @return sequence result
    def newClientCertificateSequence
      aliases = {
        "new_certinit"      => lambda { new_cert_init("Client Certificate") },
        "new_certSaveDef"   => lambda { new_cert_save_default },
        "new_cert1"         => lambda { new_cert1("Client Certificate") },
        "new_cert2"         => lambda { new_cert2("Client Certificate") },
        "new_cert3"         => lambda { new_cert3("Client Certificate") },
        "new_cert_advanced" => lambda do
          new_cert_advanced(false, "Client Certificate")
        end
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ca_mgm")
      ret = WizardSequencer(aliases, CaMgm.certificateSequence)

      UI.CloseDialog

      ret
    end


    # Dialog for revoking a certificate
    def revokeCertificate
      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(2),
          VBox(
            VSpacing(1),
            # popup window header
            Heading(_("Revoke Certificate")),
            VSpacing(1),
            Label(
              _(
                "You are only revoking the certificate. No new CRL will be created."
              )
            ),
            Frame(
              _("Reasons"),
              RadioButtonGroup(
                Id(:rb),
                VBox(
                  Left(RadioButton(Id("none"), "&no reason set", true)),
                  Left(RadioButton(Id("unspecified"), "&unspecified")),
                  Left(RadioButton(Id("keyCompromise"), "&keyCompromise")),
                  Left(RadioButton(Id("CACompromise"), "CAC&ompromise")),
                  Left(
                    RadioButton(Id("affiliationChanged"), "&affiliationChanged")
                  ),
                  Left(RadioButton(Id("superseded"), "&superseded")),
                  Left(
                    RadioButton(
                      Id("cessationOfOperation"),
                      "&cessationOfOperation"
                    )
                  ),
                  Left(RadioButton(Id("certificateHold"), "c&ertificateHold"))
                )
              )
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

      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)

        reason = Convert.to_string(UI.QueryWidget(Id(:rb), :CurrentButton))

        if ui == :ok
          # Revoke certificate
          ret = nil
          if reason != "none"
            ret = YaPI::CaManagement.RevokeCertificate(
              {
                "caName"      => CaMgm.currentCA,
                "caPasswd"    => getPassword(CaMgm.currentCA),
                "certificate" => CaMgm.currentCertificate,
                "crlReason"   => reason
              }
            )
          else
            ret = YaPI::CaManagement.RevokeCertificate(
              {
                "caName"      => CaMgm.currentCA,
                "caPasswd"    => getPassword(CaMgm.currentCA),
                "certificate" => CaMgm.currentCertificate
              }
            )
          end
          Builtins.y2milestone(
            "RevokeCertificate(%1) return %2",
            {
              "caName"      => CaMgm.currentCA,
              "certificate" => CaMgm.currentCertificate,
              "crlReason"   => reason
            },
            ret
          )
          if ret == nil || ret == false
            showErrorCaManagement
            ret = false
          end
        end
      end until Builtins.contains([:ok, :cancel], ui)
      UI.CloseDialog

      nil
    end


    # showLongCertDescription - description of a certificate in textform
    # @param CA name , certification name
    def showLongCertDescription(_CAname, _Certname)
      ret = Convert.to_string(
        YaPI::CaManagement.ReadCertificate(
          {
            "caName"      => _CAname,
            "caPasswd"    => getPassword(_CAname),
            "certificate" => _Certname,
            "type"        => "plain"
          }
        )
      )

      Builtins.y2milestone(
        "ReadCertificate(%1,%2): %3",
        _CAname,
        _Certname,
        ret
      )
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


    # getCertDescription - description of a certificate
    # @param map of description
    # @return a string with the certification description
    def getCertDescription(certMap)
      certMap = deep_copy(certMap)
      text = _("<p><b>Description</b></p>")
      if certMap == nil
        showErrorCaManagement
        return _("\nCertificate not found")
      end
      text = Ops.add(text, "<pre>")
      text = Ops.add(
        Ops.add(text, "Fingerprint:        "),
        Ops.get_string(certMap, "FINGERPRINT", "")
      )
      dn = Ops.get_map(certMap, "DN_HASH", {})
      if Ops.greater_than(Builtins.size(dn), 0)
        text = Ops.add(
          Ops.add(text, "\nCommon Name:        "),
          Ops.get_string(Ops.get_list(dn, "CN", []), 0, "")
        )
        text = Ops.add(
          Ops.add(text, "\nOrganization:       "),
          Ops.get_string(Ops.get_list(dn, "O", []), 0, "")
        )
        text = Ops.add(
          Ops.add(text, "\nLocation:           "),
          Ops.get_string(Ops.get_list(dn, "L", []), 0, "")
        )
        text = Ops.add(
          Ops.add(text, "\nState:              "),
          Ops.get_string(Ops.get_list(dn, "ST", []), 0, "")
        )
        text = Ops.add(
          Ops.add(text, "\nCountry:            "),
          Ops.get_string(Ops.get_list(dn, "C", []), 0, "")
        )
        text = Ops.add(
          Ops.add(text, "\nEMAIL:              "),
          Ops.get_string(Ops.get_list(dn, "emailAddress", []), 0, "")
        )
      end
      text = Ops.add(
        Ops.add(text, "\nIs CA:              "),
        Ops.get_string(certMap, "IS_CA", "")
      )
      text = Ops.add(
        Ops.add(text, "\nKey Size:           "),
        Ops.get_string(certMap, "KEYSIZE", "")
      )
      text = Ops.add(
        Ops.add(text, "\nSerialnumber:       "),
        Ops.get_string(certMap, "SERIAL", "")
      )
      text = Ops.add(
        Ops.add(text, "\nVersion:            "),
        Ops.get_string(certMap, "VERSION", "")
      )
      text = Ops.add(
        Ops.add(text, "\nValid from:         "),
        Ops.get_string(certMap, "NOTBEFORE", "")
      )
      text = Ops.add(
        Ops.add(text, "\nValid to:           "),
        Ops.get_string(certMap, "NOTAFTER", "")
      )
      text = Ops.add(
        Ops.add(text, "\nalgo. of pub. Key : "),
        Ops.get_string(certMap, "PUBKEY_ALGORITHM", "")
      )
      text = Ops.add(
        Ops.add(text, "\nalgo. of signature: "),
        Ops.get_string(certMap, "SIGNATURE_ALGORITHM", "")
      )
      text = Ops.add(text, "</pre>")
      text
    end


    # Creates certikficate items
    #
    # @param name of the selected CA
    # @return a list certificate items formated for a UI table
    def getCertificateList(currentCA, password)
      result = []
      i = 0

      @certificateID = []

      ret = Convert.convert(
        YaPI::CaManagement.ReadCertificateList(
          { "caName" => currentCA, "caPasswd" => password }
        ),
        :from => "list",
        :to   => "list <map>"
      )
      if ret == nil
        showErrorCaManagement
        CaMgm.passwdMap = Builtins.remove(CaMgm.passwdMap, currentCA)
        return nil
      end
      Builtins.y2milestone("ReadCertificateList(%1): %2", currentCA, ret)


      Builtins.foreach(ret) do |element|
        # Certificate status displayed in a table (Valid, Revoked, Expired)
        st = _("Valid")
        if Ops.get_string(element, "status", "") == "revoked"
          # Certificate status displayed in a table (Valid, Revoked, Expired)
          st = _("Revoked")
        end
        if Ops.get_string(element, "status", "") == "expired"
          # Certificate status displayed in a table (Valid, Revoked, Expired)
          st = _("Expired")
        end
        result = Builtins.add(
          result,
          Item(
            Id(i),
            st,
            Ops.get_string(element, "commonName", ""),
            Ops.get_string(element, "emailAddress", ""),
            Ops.get_string(element, "organizationName", ""),
            Ops.get_string(element, "organizationalUnitName", ""),
            Ops.get_string(element, "localityName", ""),
            Ops.get_string(element, "stateOrProvinceName", ""),
            Ops.get_string(element, "country", "")
          )
        )
        @certificateID = Builtins.add(
          @certificateID,
          Ops.get_string(element, "certificate", "")
        )
        i = Ops.add(i, 1)
      end
      deep_copy(result)
    end

    # Dialog Tab - certificate -
    # @return [Yast::Term] for certificates of a selected CA
    def getCertificateTab
      password = getPassword(CaMgm.currentCA)
      return nil if password == nil

      certTermList = getCertificateList(CaMgm.currentCA, password)
      return nil if certTermList == nil

      contents = VBox(
        VSpacing(1),
        HBox(
          HSpacing(1),
          Table(
            Id(:table),
            Opt(:notify, :immediate),
            Header(
              # To translators: table headers
              _("Status"),
              _("Common Name"),
              _("E-Mail Address"),
              _("Organization"),
              _("Organizational Unit"),
              _("Locality"),
              _("State"),
              _("Country")
            ),
            certTermList
          ),
          HSpacing(1)
        ),
        HBox(HSpacing(1), RichText(Id(:textinfo), ""), HSpacing(1)),
        HBox(
          HSpacing(1),
          MenuButton(
            _("Add"),
            [
              Item(Id(:addServerCerti), _("Add Server Certificate")),
              Item(Id(:addClientCerti), _("Add Client Certificate"))
            ]
          ),
          PushButton(Id(:view), _("&View")),
          PushButton(Id(:certcpw), _("&Change Password")),
          PushButton(Id(:revoke), _("&Revoke")),
          PushButton(Id(:delete), _("&Delete")),
          HStretch(),
          MenuButton(
            Id(:export),
            _("Export"),
            [
              Item(Id(:exportFile), _("Export to File")),
              Item(Id(:exportLDAP), _("Export to LDAP")),
              Item(Id(:exportCommon), _("Export as Common Server Certificate"))
            ]
          ),
          HSpacing(1)
        ),
        VSpacing(1)
      )
      deep_copy(contents)
    end

    # Initialize the tab of the dialog
    def initCertificateTab
      anyitems = UI.QueryWidget(Id(:table), :CurrentItem) != nil
      UI.ChangeWidget(Id(:delete), :Enabled, anyitems)
      UI.ChangeWidget(Id(:revoke), :Enabled, anyitems)
      UI.ChangeWidget(Id(:view), :Enabled, anyitems)
      UI.ChangeWidget(Id(:certcpw), :Enabled, anyitems)
      UI.ChangeWidget(Id(:export), :Enabled, anyitems)

      id = Convert.to_integer(UI.QueryWidget(Id(:table), :CurrentItem))
      CaMgm.currentCertificate = Ops.get(@certificateID, id, "")

      if anyitems
        ret = Convert.to_map(
          YaPI::CaManagement.ReadCertificate(
            {
              "caName"      => CaMgm.currentCA,
              "caPasswd"    => getPassword(CaMgm.currentCA),
              "certificate" => CaMgm.currentCertificate,
              "type"        => "parsed"
            }
          )
        )
        Builtins.y2milestone(
          "ReadCertificate(%1,%2): %3",
          CaMgm.currentCA,
          CaMgm.currentCertificate,
          ret
        )

        UI.ChangeWidget(Id(:textinfo), :Value, getCertDescription(ret))

        table_item = Convert.to_term(
          UI.QueryWidget(Id(:table), term(:Item, id))
        )
        valid = Ops.get_string(table_item, 1, "") == _("Valid")
        UI.ChangeWidget(Id(:delete), :Enabled, !valid)
        UI.ChangeWidget(Id(:revoke), :Enabled, valid)
        # do not export certificates which are a CA or revoked certificate
        UI.ChangeWidget(
          Id(:export),
          :Enabled,
          valid && Ops.get_string(ret, "IS_CA", "") != "1"
        )

        opensslExtentions = Ops.get_map(ret, "OPENSSL_EXTENSIONS", {})
        first = true
        @currentSubjectAltName = ""
        Builtins.foreach(
          Convert.convert(
            Ops.get(opensslExtentions, "X509v3 Subject Alternative Name", []),
            :from => "list",
            :to   => "list <string>"
          )
        ) do |entry|
          if first
            @currentSubjectAltName = entry
            first = false
          else
            @currentSubjectAltName = Ops.add(
              Ops.add(@currentSubjectAltName, ","),
              entry
            )
          end
        end
      else
        @currentSubjectAltName = ""
      end

      nil
    end


    # Handle events in a tab of a dialog
    def handleCertificateTab(event)
      event = deep_copy(event)
      ui = Ops.get(event, "ID")

      initCertificateTab if ui == :table

      if ui == :view
        showLongCertDescription(CaMgm.currentCA, CaMgm.currentCertificate)
      end
      if ui == :certcpw
        changePassword(CaMgm.currentCA, CaMgm.currentCertificate)
      end
      if ui == :delete
        if Popup.ContinueCancelHeadline(
            _("Delete"),
            _("Delete current certificate?")
          )
          ret = nil
          ret = YaPI::CaManagement.DeleteCertificate(
            {
              "caName"      => CaMgm.currentCA,
              "certificate" => CaMgm.currentCertificate,
              "caPasswd"    => getPassword(CaMgm.currentCA)
            }
          )
          Builtins.y2milestone(
            "DeleteCertificate(%1) return %2",
            {
              "caName"      => CaMgm.currentCA,
              "certificate" => CaMgm.currentCertificate
            },
            ret
          )
          showErrorCaManagement if ret == nil || ret == false
          ui = :again
        end
      end
      if ui == :revoke
        revokeCertificate
        ui = :again
      end
      if ui == :exportFile
        exportCertificateToFile(CaMgm.currentCA, CaMgm.currentCertificate)
      end
      if ui == :exportLDAP
        id = Convert.to_integer(UI.QueryWidget(Id(:table), :CurrentItem))
        table_item = Convert.to_term(
          UI.QueryWidget(Id(:table), term(:Item, id))
        )
        exportToLDAP(
          "CERT",
          CaMgm.currentCA,
          Ops.get_string(table_item, 2, ""), #common name
          Ops.get_string(table_item, 3, ""), #EMAIL
          CaMgm.currentCertificate,
          @currentSubjectAltName
        )
      end
      if ui == :exportCommon
        id = Convert.to_integer(UI.QueryWidget(Id(:table), :CurrentItem))
        table_item = Convert.to_term(
          UI.QueryWidget(Id(:table), term(:Item, id))
        )
        exportCommonServerCertificate(
          CaMgm.currentCA,
          CaMgm.currentCertificate,
          Ops.get_string(table_item, 2, "")
        )
      end
      if ui == :addServerCerti
        newServerCertificateSequence
        ui = :again
      end
      if ui == :addClientCerti
        newClientCertificateSequence
        ui = :again
      end

      Convert.to_symbol(ui)
    end
  end
end
