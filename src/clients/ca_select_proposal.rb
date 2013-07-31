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
# File:
#	ca_select_proposal.ycp
#
# Module:
#	ca_select_proposal.ycp
#
# Authors:
#	Stefan Schubert <schubi@suse.de>
#
# Summary:
#
#
# $Id$
#
module Yast
  class CaSelectProposalClient < Client
    def main
      Yast.import "UI"
      textdomain "ca-management"
      Yast.import "CaMgm"

      Yast.import "Mode"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "Popup"

      Yast.include self, "ca-management/popup.rb"
      Yast.include self, "ca-management/util.rb"



      # ----------------------------------------------------------------------
      # MAIN module
      # ----------------------------------------------------------------------
      Wizard.CreateDialog
      Wizard.SetDesktopIcon("ca_mgm")

      @heading = _("Managing CAs and Certificates")

      @contents = Frame(
        _("Selection"),
        RadioButtonGroup(
          Id(:rb),
          VBox(
            Left(
              RadioButton(
                Id(:def),
                Opt(:notify),
                _("Create &Default CA and Certificate")
              )
            ),
            HBox(
              HSpacing(3),
              Left(
                PushButton(
                  Id(:change),
                  Opt(:notify),
                  _("Edit Default &Settings")
                )
              )
            ),
            Left(
              RadioButton(
                Id(:none),
                Opt(:notify),
                _("Do &Not Create CA and Certificate")
              )
            ),
            Left(
              RadioButton(
                Id(:disk),
                Opt(:notify),
                _("Import CA and Certificate from D&isk")
              )
            )
          )
        )
      )

      @help_text = _(
        "<p>\n" +
          "In this frame, select the desired installation method for <b>CAs</b> and <b>certificates</b>\n" +
          "while completing the installation.\n" +
          "</p>\n"
      )

      @help_text = Ops.add(
        @help_text,
        _(
          "<p>\n" +
            "You also have the possibility of creating the default CA and certificate in the installed system \n" +
            "if you do not want to create or import it now.\n" +
            "</p>\n"
        )
      )

      # Screen title for the first interactive dialog
      Wizard.SetContentsButtons(
        @heading,
        @contents,
        @help_text,
        Label.BackButton,
        Label.NextButton
      )

      UI.ChangeWidget(Id(:rb), :CurrentButton, CaMgm.prop_selection)


      # Get the user input.
      #
      @ret = nil
      begin
        UI.ChangeWidget(
          Id(:change),
          :Enabled,
          UI.QueryWidget(Id(:rb), :CurrentButton) == :def
        )

        @ret = Wizard.UserInput

        if @ret == :next || @ret == :rb
          # Get selection
          #
          CaMgm.prop_selection = Convert.to_symbol(
            UI.QueryWidget(Id(:rb), :CurrentButton)
          )
        end
        if @ret == :change
          @ret = editDefaultEntries
          @ret = :again if @ret != :abort
        end
      end until @ret == :next || @ret == :abort || @ret == :back

      UI.CloseDialog

      Convert.to_symbol(@ret)
    end

    # Creates Country items
    # @return a list country items formated for a UI table
    def getPropCountryList
      result = []
      country_map = Convert.convert(
        Builtins.eval(SCR.Read(path(".target.yast2"), "country.ycp")),
        :from => "any",
        :to   => "map <string, string>"
      )

      country_index = Builtins.mapmap(country_map) { |k, v| { v => k } }

      name_list = Builtins.maplist(country_map) { |k, v| v }

      name_list = Builtins.sort(name_list)

      Builtins.foreach(name_list) do |name|
        result = Builtins.add(
          result,
          Item(
            Id(Ops.get(country_index, name, "")),
            name,
            CaMgm.prop_country == Ops.get(country_index, name, "")
          )
        )
      end
      deep_copy(result)
    end

    def editAltNames(initial_set)
      initial_set = deep_copy(initial_set)
      alt_dialog = HBox(
        VSpacing(10),
        VBox(
          HSpacing(10),
          RadioButtonGroup(
            Id(:rb),
            HBox(
              RadioButton(Id("URI"), Opt(:notify), "URI", true),
              RadioButton(Id("email"), Opt(:notify), "email"),
              RadioButton(Id("DNS"), Opt(:notify), "DNS"),
              RadioButton(Id("IP"), Opt(:notify), "IP"),
              RadioButton(Id("RID"), Opt(:notify), "RID"),
              RadioButton(Id("MS-UPN"), Opt(:notify), "MS-UPN"),
              RadioButton(Id("K5PN"), Opt(:notify), "K5PN")
            )
          ),
          TextEntry(Id(:name), _("&Name:")),
          # push button label
          HBox(
            PushButton(Id(:cancel), Opt(:key_F9), Label.CancelButton),
            HStretch(),
            PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton)
          ),
          HSpacing(10)
        ),
        VSpacing(10)
      )
      UI.OpenDialog(
        VBox(
          Left(
            CheckBox(
              Id(:id_adv_cri_subject_alt_name),
              _("critical"),
              CaMgm.prop_adv_cri_issuer_alt_name
            )
          ),
          VSpacing(1.5),
          HBox(
            VSpacing(5),
            HWeight(
              3,
              Table(
                Id(:id_adv_subject_alt_name),
                Header(
                  # To translators: table headers
                  _("Kind"),
                  _("Name")
                )
              )
            ),
            HWeight(
              1,
              VBox(
                HBox(
                  HWeight(
                    1,
                    PushButton(Id(:add), Opt(:key_F3), Label.AddButton)
                  )
                ),
                HBox(
                  HWeight(
                    1,
                    PushButton(Id(:edit), Opt(:key_F3), Label.EditButton)
                  )
                ),
                HBox(
                  HWeight(
                    1,
                    PushButton(Id(:delete), Opt(:key_F5), Label.DeleteButton)
                  )
                ),
                VStretch()
              )
            )
          ),
          VSpacing(1.5),
          ButtonBox(
            PushButton(Id(:ok), Opt(:key_F10), Label.OKButton),
            PushButton(Id(:cancel), Opt(:key_F9, :default), Label.CancelButton)
          )
        )
      )
      ret = nil
      begin
        i = 0
        table_list = Builtins.maplist(initial_set) do |element|
          i = Ops.add(i, 1)
          Item(
            Id(i),
            Ops.get_string(element, "kind", ""),
            Ops.get_string(element, "name", "")
          )
        end
        UI.ChangeWidget(Id(:id_adv_subject_alt_name), :Items, table_list)
        ret = UI.UserInput
        if ret == :add || ret == :edit
          current_kind = ""
          current_name = ""
          if ret == :edit
            current_item = Convert.to_integer(
              UI.QueryWidget(Id(:id_adv_subject_alt_name), :CurrentItem)
            )
            table_item = Convert.to_term(
              UI.QueryWidget(
                Id(:id_adv_subject_alt_name),
                term(:Item, current_item)
              )
            )
            if table_item == nil
              Popup.Error(_("No item has been selected."))
              next
            end

            current_kind = Ops.get_string(table_item, 1, "")
            current_name = Ops.get_string(table_item, 2, "")
          end
          UI.OpenDialog(Opt(:decorated), alt_dialog)
          UI.SetFocus(Id(:ok))
          if ret == :edit
            UI.ChangeWidget(Id(:name), :Value, current_name)
            UI.ChangeWidget(Id(:rb), :CurrentButton, current_kind)
          end
          if !CaMgm.adv_subject_alt_name_show_email
            UI.ChangeWidget(Id("email"), :Enabled, false)
          else
            UI.ChangeWidget(Id("email"), :Enabled, true)
          end
          while true
            ret2 = UI.UserInput
            if ret2 == :ok
              new_entry = ret == :add ? {} : Builtins.find(initial_set) do |m|
                Ops.get_string(m, "kind", "") == current_kind &&
                  Ops.get_string(m, "name", "") == current_name
              end
              Ops.set(
                new_entry,
                "kind",
                Convert.to_string(UI.QueryWidget(Id(:rb), :CurrentButton))
              )
              Ops.set(
                new_entry,
                "name",
                Convert.to_string(UI.QueryWidget(Id(:name), :Value))
              )
              initial_set = Builtins.add(initial_set, new_entry) if ret == :add
              break
            elsif ret2 == :cancel
              break
            end
          end
          UI.CloseDialog
        elsif ret == :delete
          current_item = Convert.to_integer(
            UI.QueryWidget(Id(:id_adv_subject_alt_name), :CurrentItem)
          )
          table_item = Convert.to_term(
            UI.QueryWidget(
              Id(:id_adv_subject_alt_name),
              term(:Item, current_item)
            )
          )

          if table_item == nil
            Popup.Error(_("No item has been selected."))
            next
          end
          current_kind = Ops.get_string(table_item, 1, "")
          current_name = Ops.get_string(table_item, 2, "")

          if Popup.YesNoHeadline(
              # To translators: ContinueCancel Popup headline
              _("Delete"),
              # To translators: ContinueCancel Popup
              _("Really delete this entry?")
            )
            initial_set = Builtins.filter(initial_set) do |element|
              Ops.get_string(element, "kind", "") != current_kind ||
                Ops.get_string(element, "name", "") != current_name
            end
          end
        end
      end while ret != :ok && ret != :cancel
      ca_crit = Convert.to_boolean(
        UI.QueryWidget(Id(:id_adv_cri_subject_alt_name), :Value)
      )
      UI.CloseDialog
      ret == :ok ? [initial_set, ca_crit] : nil
    end


    # editDefaultEntries() - changing Entries
    # @return `next,`back,`abort
    def editDefaultEntries
      Wizard.CreateDialog
      Wizard.SetDesktopIcon("ca_mgm")
      help_text = _(
        "<p>\n" +
          "YaST generates a <b>default CA and certificate</b> automatically. This CA and certificate\n" +
          "is used for communicating with the <b>Apache server</b>.\n" +
          "Here, change these <b>default settings</b>.\n" +
          "</p>\n"
      )
      confirmPassword = CaMgm.prop_password

      contents = VBox(
        HBox(
          HWeight(
            1,
            TextEntry(Id(:id_CAName), _("&CA Name:"), CaMgm.prop_CAName)
          ),
          HSpacing(2),
          HWeight(
            1,
            TextEntry(
              Id(:id_commonName),
              _("&Common Name:"),
              CaMgm.prop_ca_commonName
            )
          )
        ),
        HBox(
          HWeight(
            1,
            TextEntry(
              Id(:id_serverName),
              _("&Server Name:"),
              CaMgm.prop_server_commonName
            )
          ),
          HSpacing(2),
          HWeight(
            1,
            ComboBox(
              Id(:id_country),
              Opt(:editable),
              _("C&ountry:"),
              getPropCountryList
            )
          )
        ),
        HBox(
          HWeight(
            1,
            TextEntry(
              Id(:id_organisation),
              _("O&rganization:"),
              CaMgm.prop_organisation
            )
          ),
          HSpacing(2),
          HWeight(
            1,
            TextEntry(
              Id(:id_organisationUnit),
              _("Or&ganizational Unit:"),
              CaMgm.prop_organisationUnit
            )
          )
        ),
        HBox(
          HWeight(
            1,
            TextEntry(Id(:id_locality), _("Loca&lity:"), CaMgm.prop_locality)
          ),
          HSpacing(2),
          HWeight(1, TextEntry(Id(:id_state), _("&State:"), CaMgm.prop_state))
        ),
        HBox(
          HWeight(
            1,
            Password(
              Id(:pw1),
              Opt(:hstretch),
              _("&Password:"),
              CaMgm.prop_password
            )
          ),
          HSpacing(2),
          HWeight(
            1,
            Password(
              Id(:pw2),
              Opt(:hstretch),
              _("Co&nfirm Password"),
              confirmPassword
            )
          )
        ),
        HBox(
          HWeight(1, TextEntry(Id(:email), _("E-Mail"), CaMgm.prop_email)),
          HSpacing(2),
          HWeight(1, PushButton(Id(:alt), _("&Edit Alternative Names")))
        )
      )

      # Screen title for the first interactive dialog
      Wizard.SetContentsButtons(
        _("Edit Default Settings"),
        contents,
        help_text,
        Label.BackButton,
        Label.NextButton
      )


      valid_chars = ",.:;#'+*~?][(){}/\u00A7&%$\"!@0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_- "
      UI.ChangeWidget(Id(:id_commonName), :ValidChars, valid_chars)
      UI.ChangeWidget(Id(:id_organisation), :ValidChars, valid_chars)
      UI.ChangeWidget(Id(:id_organisationUnit), :ValidChars, valid_chars)
      UI.ChangeWidget(Id(:id_locality), :ValidChars, valid_chars)
      UI.ChangeWidget(Id(:id_state), :ValidChars, valid_chars)
      Builtins.y2milestone("%1", valid_chars)
      UI.ChangeWidget(
        Id(:id_CAName),
        :ValidChars,
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"
      )

      # Get the user input.
      #
      ret = nil
      temp_alt_names = deep_copy(CaMgm.prop_subject_alt_name_list)
      temp_cri_alt = CaMgm.prop_adv_cri_issuer_alt_name
      begin
        ret = Wizard.UserInput

        if ret == :alt
          new_alt_names = editAltNames(temp_alt_names)
          if new_alt_names != nil
            temp_alt_names = Convert.convert(
              Ops.get(Convert.to_list(new_alt_names), 0, temp_alt_names),
              :from => "any",
              :to   => "list <map>"
            )
          end
          temp_cri_alt = Ops.get_boolean(
            Convert.to_list(new_alt_names),
            1,
            temp_cri_alt
          )
        elsif ret == :next || ret == :back
          confirmPassword = Convert.to_string(UI.QueryWidget(Id(:pw2), :Value))
          if Convert.to_string(UI.QueryWidget(Id(:pw1), :Value)) != confirmPassword
            Popup.Error(_("New passwords do not match."))
            ret = :again
          elsif Ops.less_than(Builtins.size(confirmPassword), 4)
            Popup.Error(
              _("Password length should be greater than three characters.")
            )
            ret = :again
          else
            if CaMgm.prop_ca_commonName !=
                Convert.to_string(UI.QueryWidget(Id(:id_commonName), :Value))
              CaMgm.prop_ca_commonName = Convert.to_string(
                UI.QueryWidget(Id(:id_commonName), :Value)
              )
              CaMgm.prop_ca_commonNameChanged = true
            end
            if CaMgm.prop_server_commonName !=
                Convert.to_string(UI.QueryWidget(Id(:id_serverName), :Value))
              CaMgm.prop_server_commonName = Convert.to_string(
                UI.QueryWidget(Id(:id_serverName), :Value)
              )
              CaMgm.prop_server_commonNameChanged = true
            end
            if CaMgm.prop_CAName !=
                Convert.to_string(UI.QueryWidget(Id(:id_CAName), :Value))
              CaMgm.prop_CAName = Convert.to_string(
                UI.QueryWidget(Id(:id_CAName), :Value)
              )
              CaMgm.prop_CANameChanged = true
            end
            if CaMgm.prop_password !=
                Convert.to_string(UI.QueryWidget(Id(:pw1), :Value))
              CaMgm.prop_password = Convert.to_string(
                UI.QueryWidget(Id(:pw1), :Value)
              )
              CaMgm.prop_passwordChanged = true
            end
            if CaMgm.prop_country !=
                Convert.to_string(UI.QueryWidget(Id(:id_country), :Value))
              CaMgm.prop_country = Convert.to_string(
                UI.QueryWidget(Id(:id_country), :Value)
              )
              CaMgm.prop_countryChanged = true
            end
            if CaMgm.prop_email !=
                Convert.to_string(UI.QueryWidget(Id(:email), :Value))
              if check_mail_address(
                  Convert.to_string(UI.QueryWidget(Id(:email), :Value))
                )
                CaMgm.prop_email = Convert.to_string(
                  UI.QueryWidget(Id(:email), :Value)
                )
                CaMgm.prop_emailChanged = true
              else
                Popup.Error(_("Invalid e-mail format."))
                ret = :again
              end
            end

            CaMgm.prop_organisation = Convert.to_string(
              UI.QueryWidget(Id(:id_organisation), :Value)
            )
            CaMgm.prop_organisationUnit = Convert.to_string(
              UI.QueryWidget(Id(:id_organisationUnit), :Value)
            )
            CaMgm.prop_locality = Convert.to_string(
              UI.QueryWidget(Id(:id_locality), :Value)
            )
            CaMgm.prop_state = Convert.to_string(
              UI.QueryWidget(Id(:id_state), :Value)
            )
            CaMgm.prop_subject_alt_name_list = deep_copy(temp_alt_names)
            CaMgm.prop_adv_cri_issuer_alt_name = temp_cri_alt
            Builtins.y2milestone(
              "alt names %1",
              CaMgm.prop_subject_alt_name_list
            )
          end
        end
      end until ret == :next || ret == :abort || ret == :back

      UI.CloseDialog
      deep_copy(ret)
    end
  end
end

Yast::CaSelectProposalClient.new.main
