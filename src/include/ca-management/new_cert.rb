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
#   new_cert.ycp
#
# Module:
#   CA Management
#
# Summary:
#   Creating a new CA/Certificate
#
# Authors:
#   Stefan Schubert <schubi@suse.de>
#
# $Id$
#
# Creating a new CA/Certificate
#
module Yast
  module CaManagementNewCertInclude
    def initialize_ca_management_new_cert(include_target)
      Yast.import "UI"

      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/util.rb"
      Yast.include include_target, "ca-management/new_cert_read_write.rb"
    end

    # Creates EMAIL items
    # @return a list EMAIL items formated for a UI table
    def getEMAILList
      result = []
      i = 0

      Builtins.foreach(CaMgm.emailList) do |element|
        result = Builtins.add(
          result,
          Item(
            Id(i),
            Ops.get_string(element, "name", ""),
            Ops.get_boolean(element, "default", false) ?
              UI.Glyph(:CheckMark) :
              ""
          )
        )
        i = Ops.add(i, 1)
      end
      deep_copy(result)
    end



    # Creating new CA/Certificate ( 1. step )
    # @param [String] kind ("Root CA","Sub CA","Client Certificate","Server Certificate","Client Request","Server Request","Sub CA Request")
    # @return `next, 'abort, 'again
    def new_cert1(kind)
      helptext = ""
      # help text 1/7
      if kind == "Root CA" || kind == "Sub CA"
        helptext = _("<p>To generate a new CA, some entries are needed.</p>")
      elsif kind == "Client Certificate" || kind == "Server Certificate"
        helptext = _(
          "<p>To generate a new certificate, some entries are needed.</p>"
        )
      elsif kind == "Client Request" || kind == "Server Request" ||
          kind == "Sub CA Request"
        helptext = _(
          "<p>To generate a new request, some entries are needed.</p>"
        )
      else
        helptext = "<p>ERROR Wrong kind. FIX IT</p>"
      end

      # help text 2/7
      helptext = Ops.add(
        helptext,
        _("<p>It depends on the policy defined in the configuration file.</p>")
      )
      # help text 4/7
      helptext = Ops.add(
        helptext,
        _("<p>Only US ASCII characters are allowed.</p>")
      )
      # help text 5/7
      if kind == "Root CA" || kind == "Sub CA"
        helptext = Ops.add(
          helptext,
          _(
            "<p><b>CA Name</b> is the name of a CA certificate. Use only the characters, \"a-z\", \"A-Z\", \"-\", and \"_\".</p>"
          )
        )
        helptext = Ops.add(
          helptext,
          _("<p><b>Common Name</b> is the name of the CA.</p>")
        )
      else
        if kind == "Client Certificate" || kind == "Client Request"
          helptext = Ops.add(
            helptext,
            _(
              "<p><b>Common Name</b> is the name of the user for whom to create the certificate.</p>"
            )
          )
        else
          helptext = Ops.add(
            helptext,
            _(
              "<p><b>Common Name</b> is the fully qualified domain name of the server.</p>"
            )
          )
        end
      end
      # help text 6/7
      helptext = Ops.add(
        helptext,
        _(
          "<p><b>E-Mail Addresses</b> are valid e-mail addresses of the user or server administrator.</p>"
        )
      )
      # help text 7/7
      helptext = Ops.add(
        helptext,
        _(
          "<p><b>Organization</b>, <b>Organizational Unit</b>, <b>Locality</b>, and <b>State</b> are often optional.</p>"
        )
      )


      emailTermList = getEMAILList

      buttons = VBox()
      # To translators: pushbutton label
      buttons = Builtins.add(
        buttons,
        HBox(
          HWeight(
            1,
            PushButton(Id(:deleteEmail), Opt(:key_F5), Label.DeleteButton)
          )
        )
      )
      buttons = Builtins.add(
        buttons,
        HBox(HWeight(1, PushButton(Id(:defaultEmail), _("D&efault"))))
      )
      buttons = Builtins.add(buttons, VStretch())
      # To translators: pushbutton label
      buttons = Builtins.add(
        buttons,
        HBox(
          HWeight(1, PushButton(Id(:addEmail), Opt(:key_F3), Label.AddButton))
        )
      )

      editEmail = VBox()
      editEmail = Builtins.add(
        editEmail,
        HBox(
          VSpacing(5),
          Table(
            Id(:table),
            Opt(:notify, :immediate),
            Header(
              # To translators: table headers
              _("E-Mail Addresses"),
              _("default")
            ),
            emailTermList
          )
        )
      )
      editEmail = Builtins.add(editEmail, TextEntry(Id(:id_emailname), ""))

      emails = HBox()
      emails = Builtins.add(emails, HWeight(3, editEmail))
      emails = Builtins.add(emails, HWeight(1, buttons))

      contents = VBox()
      if kind == "Root CA" || kind == "Sub CA"
        contents = Builtins.add(
          contents,
          TextEntry(Id(:id_CAName), _("&CA Name:"), CaMgm.CAName)
        )
      end
      contents = Builtins.add(
        contents,
        TextEntry(Id(:id_commonName), _("&Common Name:"), CaMgm.commonName)
      )
      contents = Builtins.add(contents, emails)
      contents = Builtins.add(contents, VSpacing(2))
      contents = Builtins.add(
        contents,
        HBox(
          HWeight(
            1,
            TextEntry(
              Id(:id_organisation),
              _("O&rganization:"),
              CaMgm.organisation
            )
          ),
          HSpacing(2),
          HWeight(
            1,
            TextEntry(
              Id(:id_organisationUnit),
              _("Or&ganizational Unit:"),
              CaMgm.organisationUnit
            )
          )
        )
      )
      contents = Builtins.add(
        contents,
        HBox(
          HWeight(
            1,
            TextEntry(Id(:id_locality), _("Loca&lity:"), CaMgm.locality)
          ),
          HSpacing(2),
          HWeight(1, TextEntry(Id(:id_state), _("&State:"), CaMgm.state))
        )
      )

      contents = Builtins.add(
        contents,
        HBox(
          HWeight(
            1,
            ComboBox(
              Id(:id_country),
              Opt(:editable),
              _("C&ountry:"),
              getCountryList
            )
          )
        )
      )

      # To translators: dialog label

      Wizard.SetContents(
        Ops.add(Ops.add(_("Create New "), kind), _(" (step 1/3)")),
        contents,
        helptext,
        true,
        true
      )
      Wizard.RestoreNextButton
      Wizard.DisableBackButton
      valid_chars = ",.:;#'+*~?][(){}/\u00A7&%$\"!@0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_- "
      UI.ChangeWidget(Id(:id_commonName), :ValidChars, valid_chars)
      UI.ChangeWidget(Id(:id_organisation), :ValidChars, valid_chars)
      UI.ChangeWidget(Id(:id_organisationUnit), :ValidChars, valid_chars)
      UI.ChangeWidget(Id(:id_locality), :ValidChars, valid_chars)
      UI.ChangeWidget(Id(:id_state), :ValidChars, valid_chars)
      Builtins.y2milestone("%1", valid_chars)
      if kind == "Root CA" || kind == "Sub CA"
        UI.ChangeWidget(
          Id(:id_CAName),
          :ValidChars,
          "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"
        )
        UI.SetFocus(Id(:id_CAName))
      end
      ui = nil
      begin
        anyitems = UI.QueryWidget(Id(:table), :CurrentItem) != nil
        UI.ChangeWidget(Id(:deleteEmail), :Enabled, anyitems)
        UI.ChangeWidget(Id(:defaultEmail), :Enabled, anyitems)

        ui = Convert.to_symbol(UI.UserInput)

        if ui == :next || ui == :addEmail || ui == :deleteEmail ||
            ui == :defaultEmail
          CaMgm.commonName = Convert.to_string(
            UI.QueryWidget(Id(:id_commonName), :Value)
          )
          if kind == "Root CA" || kind == "Sub CA"
            CaMgm.CAName = Convert.to_string(
              UI.QueryWidget(Id(:id_CAName), :Value)
            )
          end
          CaMgm.organisation = Convert.to_string(
            UI.QueryWidget(Id(:id_organisation), :Value)
          )
          CaMgm.organisationUnit = Convert.to_string(
            UI.QueryWidget(Id(:id_organisationUnit), :Value)
          )
          CaMgm.locality = Convert.to_string(
            UI.QueryWidget(Id(:id_locality), :Value)
          )
          CaMgm.state = Convert.to_string(UI.QueryWidget(Id(:id_state), :Value))
          CaMgm.country = Convert.to_string(
            UI.QueryWidget(Id(:id_country), :Value)
          )

          if ui == :addEmail
            selection = {}
            Ops.set(
              selection,
              "name",
              Convert.to_string(UI.QueryWidget(Id(:id_emailname), :Value))
            )
            if Ops.greater_than(Builtins.size(CaMgm.emailList), 0)
              Ops.set(selection, "default", false)
            else
              Ops.set(selection, "default", true)
            end

            if Ops.greater_than(
                Builtins.size(Ops.get_string(selection, "name", "")),
                0
              )
              if check_mail_address(Ops.get_string(selection, "name", ""))
                CaMgm.emailList = Builtins.add(CaMgm.emailList, selection)
              else
                Popup.Error(_("Invalid e-mail format."))
                UI.SetFocus(Id(:id_emailname))
              end
            end
            ui = :again
          end
          if ui == :deleteEmail
            id = Convert.to_integer(UI.QueryWidget(Id(:table), :CurrentItem))
            table_item = Convert.to_term(
              UI.QueryWidget(Id(:table), term(:Item, id))
            )
            current_name = Ops.get_string(table_item, 1, "")
            dummy_map = []

            #finding entry in list
            Builtins.foreach(CaMgm.emailList) do |element|
              if Ops.get_string(element, "name", "") != current_name
                dummy_map = Builtins.add(dummy_map, element)
              end
            end

            CaMgm.emailList = deep_copy(dummy_map)

            ui = :again
          end
          if ui == :defaultEmail
            id = Convert.to_integer(UI.QueryWidget(Id(:table), :CurrentItem))
            table_item = Convert.to_term(
              UI.QueryWidget(Id(:table), term(:Item, id))
            )
            current_name = Ops.get_string(table_item, 1, "")
            dummy_map = []

            #finding entry in list
            Builtins.foreach(CaMgm.emailList) do |element|
              if Ops.get_string(element, "name", "") == current_name
                Ops.set(element, "default", true)
              else
                Ops.set(element, "default", false)
              end
              dummy_map = Builtins.add(dummy_map, element)
            end

            CaMgm.emailList = deep_copy(dummy_map)

            ui = :again
          end
          if ui == :next
            if (kind == "Root CA" || kind == "Sub CA") &&
                Ops.less_or_equal(Builtins.size(CaMgm.CAName), 0)
              UI.SetFocus(Id(:id_CAName))
              Popup.Error(_("CA name required."))
              ui = :again
            end
            if Ops.less_or_equal(Builtins.size(CaMgm.commonName), 0)
              UI.SetFocus(Id(:id_commonName))
              Popup.Error(_("Common name required."))
              ui = :again
            end

            # Checking if there is an EMAIL entry without using the
            # "add" button
            selection = {}
            Ops.set(
              selection,
              "name",
              Convert.to_string(UI.QueryWidget(Id(:id_emailname), :Value))
            )
            if Ops.greater_than(
                Builtins.size(Ops.get_string(selection, "name", "")),
                0
              )
              if Ops.greater_than(Builtins.size(CaMgm.emailList), 0)
                Ops.set(selection, "default", false)
              else
                Ops.set(selection, "default", true)
              end

              if check_mail_address(Ops.get_string(selection, "name", ""))
                CaMgm.emailList = Builtins.add(CaMgm.emailList, selection)
              else
                Popup.Error(_("Invalid e-mail format."))
                UI.SetFocus(Id(:id_emailname))
                ui = :again
              end
            end
            if Ops.less_or_equal(Builtins.size(CaMgm.emailList), 0)
              # Is has no sense to copy standard email address to subject alt name if there is none.
              CaMgm.adv_copy_subject_alt_name = false
            end
            if kind == "Root CA"
              # Root Ca
              # If the own "Subject Alt Name" is defined, the copy will be allowed
              if CaMgm.adv_cri_subject_alt_name ||
                  CaMgm.adv_copy_subject_alt_name ||
                  Ops.greater_than(
                    Builtins.size(CaMgm.adv_subject_alt_name_list),
                    0
                  )
                CaMgm.adv_copy_issuer_alt_name_enabled = true
              else
                CaMgm.adv_copy_issuer_alt_name = false
                CaMgm.adv_copy_issuer_alt_name_enabled = false
              end
            end
          end
        end
        ui = :abort if ui == :cancel
      end until Builtins.contains([:back, :again, :next, :abort], ui)

      ui
    end


    # Creating new CA/Certificate ( 2. step )
    # @param [String] kind ("Root CA","Sub CA","Client Certificate","Server Certificate","Client Request","Server Request", "Sub CA Request")
    # @return `next, 'back, 'cancel, `advancedOptions
    def new_cert2(kind)
      helptext = "Help text not found; please fix"

      if kind == "Root CA" || kind == "Sub CA"
        # help text 1/4
        helptext = _(
          "<p>The private key of the CA needs a <B>Password</B> with a minimum length of five characters. For verification reasons, reenter it in the next field.</p>"
        )

        # help text 2/4
        helptext = Ops.add(
          helptext,
          _(
            "<p>Each CA has its own <b>Key Length</b>. Some applications that use certificates need special key lengths.</p>"
          )
        )

        # help text 3/4
        helptext = Ops.add(
          helptext,
          _(
            "<p>The CA is valid for only specific period (<b>Valid Period</b>). Enter the time frame in days.</p>"
          )
        )

        # help text 4/4
        helptext = Ops.add(
          helptext,
          _(
            "<p><b>Advanced Options</b> are very special options. If you change these options, SUSE cannot guarantee that the generated certificate will work correctly.</p>"
          )
        )
      elsif kind == "Client Certificate" || kind == "Server Certificate"
        # help text 1/4
        helptext = _(
          "<p>The private key of the certificate needs a <B>Password</B> with a minimum length of five characters. For verification reasons, reenter it in the next field.</p>"
        )

        # help text 2/4
        helptext = Ops.add(
          helptext,
          _(
            "<p>Each certificate has its own <b>Key Length</b>. Some applications that use certificates need special key lengths.</p>"
          )
        )

        # help text 3/4
        helptext = Ops.add(
          helptext,
          _(
            "<p>The certificate is valid for only specific period (<b>Valid Period</b>). Enter the time frame in days.</p>"
          )
        )

        # help text 4/4
        helptext = Ops.add(
          helptext,
          _(
            "<p><b>Advanced Options</b> are very special options. If you change these options, SUSE cannot guarantee that the generated certificate will work correctly.</p>"
          )
        )
      elsif kind == "Client Request" || kind == "Server Request" ||
          kind == "Sub CA Request"
        # help text 1/3
        helptext = _(
          "<p>The private key of the request needs a <B>Password</B> with a minimum length of five characters. For verification reasons, reenter it in the next field.</p>"
        )

        # help text 2/3
        helptext = Ops.add(
          helptext,
          _(
            "<p>Each request has its own <b>Key Length</b>. Some applications that use certificates need special key lengths.</p>"
          )
        )

        # help text 3/3
        helptext = Ops.add(
          helptext,
          _(
            "<p><b>Advanced Options</b> are very special options. If you change these options, SUSE cannot guarantee that the generated certificate will work correctly.</p>"
          )
        )
      end

      contents = VBox()
      capasswd = ""

      if CaMgm.currentCA != "" &&
          Ops.get_string(CaMgm.passwdMap, CaMgm.currentCA, "") != ""
        capasswd = Ops.get_string(CaMgm.passwdMap, CaMgm.currentCA, "")
        contents = Builtins.add(
          contents,
          Left(
            CheckBox(
              Id(:id_useCaPw),
              Opt(:notify, :immediate),
              _("&Use CA Password as Certificate Password"),
              false
            )
          )
        )
      end

      contents = Builtins.add(
        contents,
        Password(
          Id(:id_password),
          Opt(:hstretch),
          _("&Password:"),
          CaMgm.password
        )
      )
      contents = Builtins.add(
        contents,
        Password(
          Id(:id_verifyPassword),
          Opt(:hstretch),
          _("V&erify Password:"),
          CaMgm.verifyPassword
        )
      )
      contents = Builtins.add(
        contents,
        IntField(
          Id(:id_keyLength),
          _("&Key Length (bit):"),
          100,
          9999,
          CaMgm.keyLength
        )
      )
      if kind != "Client Request" && kind != "Server Request" &&
          kind != "Sub CA Request"
        contents = Builtins.add(
          contents,
          IntField(
            Id(:id_validPeriod),
            _("&Valid Period (days):"),
            1,
            10000,
            CaMgm.validPeriod
          )
        )
      end
      contents = Builtins.add(
        contents,
        Left(PushButton(Id(:advancedOptions), _("&Advanced Options")))
      )

      # To translators: dialog label
      Wizard.SetContents(
        Ops.add(Ops.add(_("Create New "), kind), _(" (step 2/3)")),
        contents,
        helptext,
        true,
        true
      )
      Wizard.RestoreNextButton

      if CaMgm.currentCA != "" &&
          Ops.get_string(CaMgm.passwdMap, CaMgm.currentCA, "") != ""
        UI.SetFocus(Id(:id_useCaPw))
      else
        UI.SetFocus(Id(:id_password))
      end

      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)

        if ui == :next || ui == :advancedOptions
          if capasswd != "" &&
              Convert.to_boolean(UI.QueryWidget(Id(:id_useCaPw), :Value))
            CaMgm.password = capasswd
            CaMgm.verifyPassword = capasswd
          else
            CaMgm.password = Convert.to_string(
              UI.QueryWidget(Id(:id_password), :Value)
            )
            CaMgm.verifyPassword = Convert.to_string(
              UI.QueryWidget(Id(:id_verifyPassword), :Value)
            )
          end
          CaMgm.keyLength = Convert.to_integer(
            UI.QueryWidget(Id(:id_keyLength), :Value)
          )

          if kind != "Client Request" && kind != "Server Request" &&
              kind != "Sub CA Request"
            CaMgm.validPeriod = Convert.to_integer(
              UI.QueryWidget(Id(:id_validPeriod), :Value)
            )
          end

          if CaMgm.password != CaMgm.verifyPassword
            UI.SetFocus(Id(:id_verifyPassword))
            Popup.Error(_("Passwords are different."))
            ui = :again
          end
          if ui == :next
            if Ops.less_or_equal(Builtins.size(CaMgm.password), 0)
              UI.SetFocus(Id(:id_password))
              Popup.Error(_("Password required."))
              ui = :again
            end
          end
        end
        ui = :abort if ui == :cancel
        if ui == :id_useCaPw
          UI.ChangeWidget(
            Id(:id_password),
            :Enabled,
            !Convert.to_boolean(UI.QueryWidget(Id(:id_useCaPw), :Value))
          )
          UI.ChangeWidget(
            Id(:id_verifyPassword),
            :Enabled,
            !Convert.to_boolean(UI.QueryWidget(Id(:id_useCaPw), :Value))
          )
        end
      end until Builtins.contains([:back, :next, :abort, :advancedOptions], ui)

      ui
    end

    # Creating new CA/Certificate ( 3. step )
    # @param [String] kind ("Root CA","Sub CA","Client Certificate","Server Certificate","Client Request","Server Request", "Sub CA Request")
    # @return `next, 'back, 'cancel
    def new_cert3(kind)
      i = 0
      nextLine = false
      helptext = "Not defined; please fix"

      if kind == "Root CA" || kind == "Sub CA"
        # help text 1/2
        helptext = _(
          "<p>This frame gives an overview of all settings for the CA that will be created.</p>"
        )
        # help text 2/2
        helptext = Ops.add(
          helptext,
          _("<p>Click <b>Create</b> to generate the CA.</p>")
        )
      elsif kind == "Client Certificate" || kind == "Server Certificate"
        # help text 1/2
        helptext = _(
          "<p>This frame gives an overview of all settings for the certificate that will be created.</p>"
        )
        # help text 2/2
        helptext = Ops.add(
          helptext,
          _("<p>Click <b>Create</b> to generate the certificate.</p>")
        )
      elsif kind == "Client Request" || kind == "Server Request" ||
          kind == "Sub CA Request"
        # help text 1/2
        helptext = _(
          "<p>This frame gives an overview of all settings for the request that will be created.</p>"
        )
        # help text 2/2
        helptext = Ops.add(
          helptext,
          _("<p>Click <b>Create</b> to generate the request.</p>")
        )
      end

      text = _("<p><b>Summary</b></p>")
      text = Ops.add(text, "<br><pre>")
      if (kind == "Root CA" || kind == "Sub CA" || kind == "Sub CA Request") &&
          Ops.greater_than(Builtins.size(CaMgm.CAName), 0)
        text = Ops.add(
          Ops.add(Ops.add(text, _("CA Name:                  ")), CaMgm.CAName),
          "\n"
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.commonName), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, _("Common Name:              ")),
            CaMgm.commonName
          ),
          "\n"
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.organisation), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, _("Organization:             ")),
            CaMgm.organisation
          ),
          "\n"
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.organisationUnit), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, _("Organizational Unit:      ")),
            CaMgm.organisationUnit
          ),
          "\n"
        )
      end

      if Ops.greater_than(Builtins.size(CaMgm.emailList), 0)
        text = Ops.add(text, _("E-Mail Addresses:         "))

        i = 0
        Builtins.foreach(CaMgm.emailList) do |element|
          if i == 0
            text = Ops.add(text, Ops.get_string(element, "name", ""))
          else
            text = Ops.add(
              Ops.add(text, "                          "),
              Ops.get_string(element, "name", "")
            )
          end
          if Ops.get_boolean(element, "default", false)
            text = Ops.add(Ops.add(text, " (default)"), "\n")
          else
            text = Ops.add(text, "\n")
          end
          i = Ops.add(i, 1)
        end
        text = Ops.add(text, "\n") if i == 0
      end
      if Ops.greater_than(Builtins.size(CaMgm.locality), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, _("Locality:                 ")),
            CaMgm.locality
          ),
          "\n"
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.state), 0)
        text = Ops.add(
          Ops.add(Ops.add(text, _("State:                    ")), CaMgm.state),
          "\n"
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.country), 0)
        text = Ops.add(
          Ops.add(Ops.add(text, _("Country:                  ")), CaMgm.country),
          "\n"
        )
      end
      text = Ops.add(
        Ops.add(Ops.add(text, _("Key Length:               ")), CaMgm.keyLength),
        " bit\n"
      )
      text = Ops.add(
        Ops.add(
          Ops.add(text, _("Valid Period:             ")),
          CaMgm.validPeriod
        ),
        _(" days\n")
      )
      text = Ops.add(
        Ops.add(Ops.add(text, "Basic Constaints:         "), CaMgm.adv_ca),
        CaMgm.adv_cri_ca ? _(" (critical)\n") : "\n"
      )
      if CaMgm.adv_pathlen
        text = Ops.add(
          Ops.add(
            Ops.add(
              Ops.add(text, "                          "),
              _("Path Length ")
            ),
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
      if Ops.greater_than(Builtins.size(CaMgm.adv_challenge_password), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "Challenge Password:        "),
            CaMgm.adv_challenge_password
          ),
          "\n"
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
          CaMgm.adv_copy_subject_alt_name &&
            Ops.greater_than(Builtins.size(CaMgm.emailList), 0)
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

      if Ops.greater_than(Builtins.size(CaMgm.adv_unstructured_name), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "Unstructured Name:        "),
            CaMgm.adv_unstructured_name
          ),
          "\n"
        )
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
        Ops.add(Ops.add(_("Create New "), kind), _(" (step 3/3)")),
        contents,
        helptext,
        true,
        true
      )
      Wizard.SetNextButton(:next, Label.CreateButton)

      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)

        if ui == :next
          #creating new certificate
          if !cert_write(kind)
            showErrorCaManagement
            ui = :again
          end
        end
        ui = :abort if ui == :cancel
      end until Builtins.contains([:back, :next, :abort], ui)

      ui
    end
  end
end
