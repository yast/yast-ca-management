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
#   crlDefault.ycp
#
# Module:
#   CA Management
#
# Summary:
#   Edit CRL defaults for a selected CA
#
# Authors:
#   Stefan Schubert <schubi@suse.de>
#
# $Id$
#
# Edit CRL default for a selected CA
#
module Yast
  module CaManagementCrlDefaultInclude
    def initialize_ca_management_crlDefault(include_target)
      Yast.import "UI"

      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/util.rb"
      Yast.include include_target, "ca-management/new_cert_callbacks.rb"
    end

    # Editing CRL defaults of a selected CA
    # @param selected CA
    def editCRLDefaults(ca)
      ret = YaPI::CaManagement.ReadCRLDefaults(
        { "caName" => ca, "caPasswd" => getPassword(ca) }
      )
      Builtins.y2milestone(
        "ReadCRLDefaults(%1) return %2",
        { "caName" => ca },
        ret
      )

      CaMgm.exp_authorityKeyIdentifier = ""
      CaMgm.exp_cri_authorityKeyIdentifier = false
      CaMgm.adv_cri_issuer_alt_name = false
      CaMgm.adv_copy_issuer_alt_name = false
      CaMgm.validPeriod = 1

      dummy = Builtins.splitstring(
        Ops.get_string(ret, "authorityKeyIdentifier", ""),
        ","
      )
      counter = 0
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        valuelist = Builtins.splitstring(entry, ":")
        ident = strip(Ops.get_string(valuelist, 0, ""))
        value = strip(Ops.get_string(valuelist, 1, ""))
        if ident == "critical"
          CaMgm.exp_cri_authorityKeyIdentifier = true
        else
          if counter == 0
            CaMgm.exp_authorityKeyIdentifier = Ops.add(
              Ops.add(
                Ops.add(CaMgm.exp_authorityKeyIdentifier, ident),
                Ops.greater_than(Builtins.size(value), 0) ? ":" : ""
              ),
              value
            )
          else
            CaMgm.exp_authorityKeyIdentifier = Ops.add(
              Ops.add(
                Ops.add(Ops.add(CaMgm.exp_authorityKeyIdentifier, ","), ident),
                Ops.greater_than(Builtins.size(value), 0) ? ":" : ""
              ),
              value
            )
          end
          counter = Ops.add(counter, 1)
        end
      end

      itemList = []
      i = 0
      CaMgm.adv_issuer_alt_name_list = []
      dummy = Builtins.splitstring(
        Ops.get_string(ret, "issuerAltName", ""),
        ","
      )
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        valuelist = Builtins.splitstring(entry, ":")
        ident = strip(Ops.get_string(valuelist, 0, ""))
        value = strip(Ops.get_string(valuelist, 1, ""))
        if ident == "critical"
          CaMgm.adv_cri_issuer_alt_name = true
        elsif ident == "issuer" && value == "copy"
          CaMgm.adv_copy_issuer_alt_name = true
        else
          new_entry = {}
          Ops.set(new_entry, "kind", ident)
          Ops.set(new_entry, "name", value)
          CaMgm.adv_issuer_alt_name_list = Builtins.add(
            CaMgm.adv_issuer_alt_name_list,
            new_entry
          )
          itemList = Builtins.add(itemList, Item(Id(i), ident, value))
          i = Ops.add(i, 1)
        end
      end

      CaMgm.validPeriod = Builtins.tointeger(Ops.get_string(ret, "days", "0"))

      # help text 1/3
      helptext = _(
        "<p>When creating a new CRL, the system suggests some default values.</p>"
      )
      # help text 2/3
      helptext = Ops.add(
        helptext,
        _("<p>With this frame, change these default settings.</p>")
      )
      # help text 3/3
      helptext = Ops.add(
        helptext,
        _(
          "<p>However, the modified settings will be used for <b>new</B> entries only.</p>"
        )
      )

      contents = VBox()

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

      contents = Builtins.add(
        contents,
        Frame(
          "Authority Key Identifier",
          VBox(
            Left(
              CheckBox(
                Id(:id_exp_cri_authorityKeyIdentifier),
                _("&Critical"),
                CaMgm.exp_cri_authorityKeyIdentifier
              )
            ),
            TextEntry(
              Id(:id_exp_authorityKeyIdentifier),
              "",
              CaMgm.exp_authorityKeyIdentifier
            )
          )
        )
      )

      contents = Builtins.add(
        contents,
        Frame(
          "Issuer Alt Name",
          VBox(
            Left(
              CheckBox(
                Id(:id_adv_cri_issuer_alt_name),
                _("C&ritical"),
                CaMgm.adv_cri_issuer_alt_name
              )
            ),
            Left(
              CheckBox(
                Id(:id_adv_copy_issuer_alt_name),
                _("C&opy Subject Alternative Name from CA"),
                CaMgm.adv_copy_issuer_alt_name
              )
            ),
            HBox(
              HWeight(
                3,
                Table(
                  Id(:id_adv_issuer_alt_name),
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
                      PushButton(Id(:modify), Opt(:key_F3), Label.EditButton)
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
            )
          )
        )
      )

      Wizard.CreateDialog
      Wizard.SetContentsButtons(
        _("Default CRL Settings"),
        contents,
        helptext,
        Label.BackButton,
        Label.OKButton
      )

      UI.ChangeWidget(Id(:id_adv_issuer_alt_name), :Items, itemList)

      Wizard.DisableBackButton

      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)

        CaMgm.adv_cri_issuer_alt_name = Convert.to_boolean(
          UI.QueryWidget(Id(:id_adv_cri_issuer_alt_name), :Value)
        )
        CaMgm.adv_copy_issuer_alt_name = Convert.to_boolean(
          UI.QueryWidget(Id(:id_adv_copy_issuer_alt_name), :Value)
        )
        CaMgm.exp_cri_authorityKeyIdentifier = Convert.to_boolean(
          UI.QueryWidget(Id(:id_exp_cri_authorityKeyIdentifier), :Value)
        )
        CaMgm.exp_authorityKeyIdentifier = Convert.to_string(
          UI.QueryWidget(Id(:id_exp_authorityKeyIdentifier), :Value)
        )
        CaMgm.validPeriod = Convert.to_integer(
          UI.QueryWidget(Id(:id_validPeriod), :Value)
        )

        add_advanced_issuer_alt_name if ui == :add

        delete_advanced_issuer_alt_name if ui == :delete

        modify_advanced_issuer_alt_name if ui == :modify

        if ui == :next
          param = {}

          if Ops.greater_than(Builtins.size(CaMgm.adv_issuer_alt_name_list), 0) ||
              CaMgm.adv_copy_issuer_alt_name
            prevFound = false
            if CaMgm.adv_cri_issuer_alt_name
              Ops.set(param, "issuerAltName", "critical")
              prevFound = true
            else
              Ops.set(param, "issuerAltName", "")
            end
            Builtins.foreach(CaMgm.adv_issuer_alt_name_list) do |element|
              Ops.set(
                param,
                "issuerAltName",
                Ops.add(
                  Ops.add(
                    Ops.add(
                      Ops.add(
                        Ops.get_string(param, "issuerAltName", ""),
                        prevFound ? "," : ""
                      ),
                      Ops.get_string(element, "kind", "")
                    ),
                    ":"
                  ),
                  Ops.get_string(element, "name", "")
                )
              )
              prevFound = true
            end
            if CaMgm.adv_copy_issuer_alt_name
              Ops.set(
                param,
                "issuerAltName",
                Ops.add(
                  Ops.add(
                    Ops.get_string(param, "issuerAltName", ""),
                    prevFound ? "," : ""
                  ),
                  "issuer:copy"
                )
              )
            end
          end

          Ops.set(param, "days", Builtins.tostring(CaMgm.validPeriod))

          if Ops.greater_than(
              Builtins.size(CaMgm.exp_authorityKeyIdentifier),
              0
            )
            if CaMgm.exp_cri_authorityKeyIdentifier
              Ops.set(
                param,
                "authorityKeyIdentifier",
                Ops.add("critical,", CaMgm.exp_authorityKeyIdentifier)
              )
            else
              Ops.set(
                param,
                "authorityKeyIdentifier",
                CaMgm.exp_authorityKeyIdentifier
              )
            end
          end

          Ops.set(param, "caName", ca)
          Ops.set(param, "caPasswd", getPassword(ca))

          writeret = YaPI::CaManagement.WriteCRLDefaults(param)

          # we do not want to log the password
          Ops.set(param, "caPasswd", "<was set>")

          Builtins.y2milestone(
            "WriteCRLDefaults(%1) return %2",
            param,
            writeret
          )
          if writeret == nil || !writeret
            showErrorCaManagement
            ui = :again
          end
        end
      end until Builtins.contains([:next, :abort], ui)

      UI.CloseDialog

      nil
    end
  end
end
