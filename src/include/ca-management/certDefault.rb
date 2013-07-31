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
  module CaManagementCertDefaultInclude
    def initialize_ca_management_certDefault(include_target)
      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/util.rb"
      Yast.include include_target, "ca-management/new_cert_read_write.rb"
    end

    # Editing default certificate settings  ( 1. step )
    # @return `next,  'abort
    def edit_default1
      # help text 1/4
      helptext = _(
        "<p>When creating a new subCA or certificate, the system suggests some default values.</p>"
      )
      # help text 2/4
      helptext = Ops.add(
        helptext,
        _("<p>With this workflow, change these default settings.</p>")
      )
      # help text 3/4
      helptext = Ops.add(
        helptext,
        _(
          "<p>However, the modified settings will be used for <b>new</B> entries only.</p>"
        )
      )
      # help text 4/4
      helptext = Ops.add(
        helptext,
        _(
          "<p>You can edit the default settings for <b>subCAs</b>, <b>client certificates</b>, and  <b>server certificates</b>.</p>"
        )
      )

      contents = VBox()

      contents = Builtins.add(
        contents,
        Frame(
          _("Default Settings for:"),
          RadioButtonGroup(
            Id(:rb),
            VBox(
              Left(RadioButton(Id("Sub CA"), _("&Sub CA"))),
              Left(
                RadioButton(Id("Client Certificate"), _("&Client Certificate"))
              ),
              Left(
                RadioButton(Id("Server Certificate"), _("S&erver Certificate"))
              )
            )
          )
        )
      )

      Wizard.SetContents(
        _("Edit Default Settings"),
        contents,
        helptext,
        true,
        true
      )
      Wizard.RestoreNextButton
      Wizard.DisableBackButton
      UI.ChangeWidget(Id(:rb), :CurrentButton, CaMgm.currentDefault)

      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)

        if ui == :next
          kind = Convert.to_string(UI.QueryWidget(Id(:rb), :CurrentButton))
          CaMgm.initializeDefault = true if kind != CaMgm.currentDefault

          if CaMgm.initializeDefault
            new_cert_init(kind)
            new_cert_save_default
            CaMgm.initializeDefault = false
          end
        end
        CaMgm.currentDefault = Convert.to_string(
          UI.QueryWidget(Id(:rb), :CurrentButton)
        )
      end until Builtins.contains([:next, :abort], ui)

      ui
    end


    # Saving default settings ( 3. step )
    # @return 'back 'cancel
    def edit_default2
      i = 0
      nextLine = false

      # help text 1/2
      helptext = _(
        "<p>This frame gives an overview of all default settings before they are saved.</p>"
      )
      # help text 2/2
      helptext = Ops.add(
        helptext,
        _("<p>Click <b>Save</b> to finish the input.</p>")
      )

      text = _("<p><b>Summary</b></p>")
      text = Ops.add(text, "<pre>")

      text = Ops.add(
        Ops.add(Ops.add(text, "Basic Constaints:         "), CaMgm.adv_ca),
        CaMgm.adv_cri_ca ? _(" (critical)\n") : "\n"
      )

      if CaMgm.adv_pathlen
        text = Ops.add(
          Ops.add(
            Ops.add(text, _("Path Length:              ")),
            CaMgm.adv_pathlenValue
          ),
          "\n"
        )
      end

      if Ops.greater_than(Builtins.size(CaMgm.adv_distribution_point), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "CRL Distribution Point:   "),
            CaMgm.adv_distribution_point
          ),
          CaMgm.adv_cri_distribution_point ? _(" (critical)\n") : "\n"
        )
      end

      if Ops.greater_than(Builtins.size(CaMgm.adv_issuer_alt_name_list), 0) ||
          CaMgm.adv_copy_issuer_alt_name
        text = Ops.add(
          Ops.add(text, "Issuer Alt Name:          "),
          CaMgm.adv_cri_issuer_alt_name ? _("(critical) ") : ""
        )
        text = Ops.add(
          text,
          CaMgm.adv_copy_issuer_alt_name ?
            _("Copy Subject Alt Name from CA") :
            ""
        )
        i = 0
        if CaMgm.adv_cri_issuer_alt_name || CaMgm.adv_copy_issuer_alt_name
          i = Ops.add(i, 1)
          text = Ops.add(text, "\n")
        end
        Builtins.foreach(CaMgm.adv_issuer_alt_name_list) do |element|
          if i == 0
            text = Ops.add(
              Ops.add(Ops.add(text, Ops.get_string(element, "kind", "")), ":"),
              Ops.get_string(element, "name", "")
            )
          else
            text = Ops.add(
              Ops.add(
                Ops.add(
                  Ops.add(text, "                          "),
                  Ops.get_string(element, "kind", "")
                ),
                ":"
              ),
              Ops.get_string(element, "name", "")
            )
          end
          text = Ops.add(text, "\n")
          i = Ops.add(i, 1)
        end
        text = Ops.add(text, "\n") if i == 0
      end

      if CaMgm.adv_digitalSignature || CaMgm.adv_nonRepudiation ||
          CaMgm.adv_cRLSign ||
          CaMgm.adv_keyEncipherment ||
          CaMgm.adv_dataEncipherment ||
          CaMgm.adv_encipherOnly ||
          CaMgm.adv_keyAgreement ||
          CaMgm.adv_keyCertSign ||
          CaMgm.adv_decipherOnly
        text = Ops.add(
          Ops.add(text, "Key Usage:                "),
          CaMgm.adv_cri_key_usage ? _("(critical)\n") : ""
        )
        nextLine = CaMgm.adv_cri_key_usage
        if CaMgm.adv_digitalSignature
          if !nextLine
            nextLine = true
            text = Ops.add(text, "digitalSignature\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "digitalSignature\n"
            )
          end
        end
        if CaMgm.adv_nonRepudiation
          if !nextLine
            nextLine = true
            text = Ops.add(text, "nonRepudiation\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "nonRepudiation\n"
            )
          end
        end
        if CaMgm.adv_cRLSign
          if !nextLine
            nextLine = true
            text = Ops.add(text, "cRLSign\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "cRLSign\n"
            )
          end
        end
        if CaMgm.adv_keyEncipherment
          if !nextLine
            nextLine = true
            text = Ops.add(text, "keyEncipherment\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "keyEncipherment\n"
            )
          end
        end
        if CaMgm.adv_dataEncipherment
          if !nextLine
            nextLine = true
            text = Ops.add(text, "dataEncipherment\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "dataEncipherment\n"
            )
          end
        end

        if CaMgm.adv_encipherOnly
          if !nextLine
            nextLine = true
            text = Ops.add(text, "encipherOnly\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "encipherOnly\n"
            )
          end
        end
        if CaMgm.adv_keyAgreement
          if !nextLine
            nextLine = true
            text = Ops.add(text, "keyAgreement\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "keyAgreement\n"
            )
          end
        end
        if CaMgm.adv_keyCertSign
          if !nextLine
            nextLine = true
            text = Ops.add(text, "keyCertSign\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "keyCertSign\n"
            )
          end
        end
        if CaMgm.adv_decipherOnly
          if !nextLine
            nextLine = true
            text = Ops.add(text, "decipherOnly\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "decipherOnly\n"
            )
          end
        end
        if !nextLine
          nextLine = true
          text = Ops.add(text, "\n")
        end
      end

      if Ops.greater_than(Builtins.size(CaMgm.adv_nsComment), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, _("nsComment:                ")),
            CaMgm.adv_nsComment
          ),
          CaMgm.adv_cri_nsComment ? _(" (critical)\n") : "\n"
        )
      end

      if CaMgm.adv_client || CaMgm.adv_server || CaMgm.adv_sslCA ||
          CaMgm.adv_email ||
          CaMgm.adv_reserved ||
          CaMgm.adv_emailCA ||
          CaMgm.adv_objsign ||
          CaMgm.adv_objCA
        text = Ops.add(
          Ops.add(text, _("nsCertType:               ")),
          CaMgm.adv_cri_nsCertType ? _(" (critical)\n") : ""
        )
        nextLine = CaMgm.adv_cri_nsCertType
        if CaMgm.adv_client
          if !nextLine
            nextLine = true
            text = Ops.add(text, "client\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "client\n"
            )
          end
        end
        if CaMgm.adv_server
          if !nextLine
            nextLine = true
            text = Ops.add(text, "server\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "server\n"
            )
          end
        end
        if CaMgm.adv_sslCA
          if !nextLine
            nextLine = true
            text = Ops.add(text, "sslCA\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "sslCA\n"
            )
          end
        end
        if CaMgm.adv_email
          if !nextLine
            nextLine = true
            text = Ops.add(text, "email\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "email\n"
            )
          end
        end
        if CaMgm.adv_reserved
          if !nextLine
            nextLine = true
            text = Ops.add(text, "reserved\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "reserved\n"
            )
          end
        end

        if CaMgm.adv_emailCA
          if !nextLine
            nextLine = true
            text = Ops.add(text, "emailCA\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "emailCA\n"
            )
          end
        end
        if CaMgm.adv_objsign
          if !nextLine
            nextLine = true
            text = Ops.add(text, "objsign\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "objsign\n"
            )
          end
        end
        if CaMgm.adv_objCA
          if !nextLine
            nextLine = true
            text = Ops.add(text, "objCA\n")
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              "objCA\n"
            )
          end
        end
        if !nextLine
          nextLine = true
          text = Ops.add(text, "\n")
        end
      end
      if Ops.greater_than(Builtins.size(CaMgm.adv_nsSslServerName), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "nsSslServerName:          "),
            CaMgm.adv_nsSslServerName
          ),
          CaMgm.adv_cri_nsSslServerName ? _(" (critical)\n") : "\n"
        )
      end

      if Ops.greater_than(Builtins.size(CaMgm.adv_subject_alt_name_list), 0) ||
          CaMgm.adv_copy_subject_alt_name
        text = Ops.add(
          Ops.add(text, "Subject Alt Name:         "),
          CaMgm.adv_cri_subject_alt_name ? _("(critical) ") : ""
        )
        text = Ops.add(
          text,
          CaMgm.adv_copy_subject_alt_name ?
            _("Copy Standard E-Mail Address") :
            ""
        )
        i = 0
        if CaMgm.adv_cri_subject_alt_name || CaMgm.adv_copy_subject_alt_name
          i = Ops.add(i, 1)
          text = Ops.add(text, "\n")
        end
        Builtins.foreach(CaMgm.adv_subject_alt_name_list) do |element|
          if i == 0
            text = Ops.add(
              Ops.add(Ops.add(text, Ops.get_string(element, "kind", "")), ":"),
              Ops.get_string(element, "name", "")
            )
          else
            text = Ops.add(
              Ops.add(
                Ops.add(
                  Ops.add(text, "                          "),
                  Ops.get_string(element, "kind", "")
                ),
                ":"
              ),
              Ops.get_string(element, "name", "")
            )
          end
          text = Ops.add(text, "\n")
          i = Ops.add(i, 1)
        end
        text = Ops.add(text, "\n") if i == 0
      end

      if Ops.greater_than(Builtins.size(CaMgm.exp_subjectKeyIdentifier), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "Subject Key Identifier:   "),
            CaMgm.exp_subjectKeyIdentifier
          ),
          CaMgm.exp_cri_subjectKeyIdentifier ? _(" (critical)\n") : "\n"
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_authorityKeyIdentifier), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "Authority Key Identifier: "),
            CaMgm.exp_authorityKeyIdentifier
          ),
          CaMgm.exp_cri_authorityKeyIdentifier ? _(" (critical)\n") : "\n"
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_netscape_nsBaseUrl), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "nsBaseUrl:                "),
            CaMgm.exp_netscape_nsBaseUrl
          ),
          CaMgm.exp_cri_netscape_nsBaseUrl ? _(" (critical)\n") : "\n"
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_netscape_nsRevocationUrl), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "nsRevocationUrl:          "),
            CaMgm.exp_netscape_nsRevocationUrl
          ),
          CaMgm.exp_cri_netscape_nsRevocationUrl ? _(" (critical)\n") : "\n"
        )
      end
      if Ops.greater_than(
          Builtins.size(CaMgm.exp_netscape_nsCaRevocationUrl),
          0
        )
        text = Ops.add(
          Ops.add(
            Ops.add(text, "nsCaRevocationUrl:        "),
            CaMgm.exp_netscape_nsCaRevocationUrl
          ),
          CaMgm.exp_cri_netscape_nsCaRevocationUrl ? _(" (critical)\n") : "\n"
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_netscape_nsRenewalUrl), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "nsRenewalUrl:             "),
            CaMgm.exp_netscape_nsRenewalUrl
          ),
          CaMgm.exp_cri_netscape_nsRenewalUrl ? _(" (critical)\n") : "\n"
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_netscape_nsCaPolicyUrl), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "nsCaPolicyUrl:            "),
            CaMgm.exp_netscape_nsCaPolicyUrl
          ),
          CaMgm.exp_cri_netscape_nsCaPolicyUrl ? _(" (critical)\n") : "\n"
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_authorityInfoAccess), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "authorityInfoAccess:      "),
            CaMgm.exp_authorityInfoAccess
          ),
          CaMgm.exp_cri_authorityInfoAccess ? _(" (critical)\n") : "\n"
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_extendedKeyUsage), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "extendedKeyUsage:         "),
            CaMgm.exp_extendedKeyUsage
          ),
          CaMgm.exp_cri_extendedKeyUsage ? _(" (critical)\n") : "\n"
        )
      end

      text = Ops.add(text, "</pre>")

      contents = VBox()
      contents = Builtins.add(contents, RichText(text))

      # To translators: dialog label
      Wizard.SetContents(
        _("Save Settings (step 3/3)"),
        contents,
        helptext,
        true,
        true
      )
      Wizard.SetNextButton(:next, Label.SaveButton)

      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)

        if ui == :next
          #creating new certificate
          if !new_cert_write_default
            showErrorCaManagement
            ui = :again
          else
            Popup.Message(_("Default has been saved."))
          end
        end
      end until Builtins.contains([:back, :next, :abort], ui)

      ui
    end
  end
end
