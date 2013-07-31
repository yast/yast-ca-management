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
#   new_cert_callbacks.ycp
#
# Module:
#   CA Management
#
# Summary:
#   Callback definitions for advanced setting ( creating
#   new certificate )
#
# Authors:
#   Stefan Schubert <schubi@suse.de>
#
# $Id$
#
# Creating a new CA/Certificate
#
module Yast
  module CaManagementNewCertCallbacksInclude
    def initialize_ca_management_new_cert_callbacks(include_target)
      Yast.import "UI"
      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "YaPI::CaManagement"


      # saved default settings
      @sav_adv_cri_ca = false
      @sav_adv_ca = "none"
      @sav_adv_pathlen = false
      @sav_adv_pathlenValue = 1

      @sav_adv_cri_distribution_point = false
      @sav_adv_distribution_point = ""

      @sav_adv_challenge_password = ""

      @sav_adv_cri_issuer_alt_name = false
      @sav_adv_copy_issuer_alt_name = false

      @sav_adv_cri_key_usage = false
      @sav_adv_digitalSignature = false
      @sav_adv_nonRepudiation = false
      @sav_adv_cRLSign = false
      @sav_adv_keyEncipherment = false
      @sav_adv_dataEncipherment = false
      @sav_adv_encipherOnly = false
      @sav_adv_keyAgreement = false
      @sav_adv_keyCertSign = false
      @sav_adv_decipherOnly = false

      @sav_adv_cri_nsComment = false
      @sav_adv_nsComment = ""

      @sav_adv_cri_nsCertType = false
      @sav_adv_client = false
      @sav_adv_server = false
      @sav_adv_sslCA = false
      @sav_adv_email = false
      @sav_adv_reserved = false
      @sav_adv_emailCA = false
      @sav_adv_objsign = false
      @sav_adv_objCA = false

      @sav_adv_cri_nsSslServerName = false
      @sav_adv_nsSslServerName = ""

      @sav_adv_cri_subject_alt_name = false
      @sav_adv_copy_subject_alt_name = false

      @sav_adv_unstructured_name = ""

      @sav_exp_cri_subjectKeyIdentifier = false
      @sav_exp_subjectKeyIdentifier = ""
      @sav_exp_cri_authorityKeyIdentifier = false
      @sav_exp_authorityKeyIdentifier = ""

      @sav_exp_cri_netscape_nsBaseUrl = false
      @sav_exp_netscape_nsBaseUrl = ""

      @sav_exp_cri_netscape_nsRevocationUrl = false
      @sav_exp_netscape_nsRevocationUrl = ""

      @sav_exp_cri_netscape_nsCaRevocationUrl = false
      @sav_exp_netscape_nsCaRevocationUrl = ""

      @sav_exp_cri_netscape_nsRenewalUrl = false
      @sav_exp_netscape_nsRenewalUrl = ""

      @sav_exp_cri_netscape_nsCaPolicyUrl = false
      @sav_exp_netscape_nsCaPolicyUrl = ""

      @sav_exp_cri_authorityInfoAccess = false
      @sav_exp_authorityInfoAccess = ""

      @sav_exp_cri_extendedKeyUsage = false
      @sav_exp_extendedKeyUsage = ""


      @issuer_box = HBox(
        VSpacing(10),
        VBox(
          HSpacing(10),
          RadioButtonGroup(
            Id(:rb),
            HBox(
              RadioButton(Id("email"), Opt(:notify), "email", true),
              RadioButton(Id("URI"), Opt(:notify), "URI"),
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


      @subject_box = HBox(
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
    end

    # Resetting accept checkbox for the request extentions
    # Especially used for signing a request
    # @param request extention
    def resetAcceptRequestExtention(extention)
      if Builtins.contains(CaMgm.slectedRequestExtention, extention)
        dummy = []
        Builtins.foreach(CaMgm.slectedRequestExtention) do |entry|
          dummy = Builtins.add(dummy, entry) if entry != extention
        end
        CaMgm.slectedRequestExtention = deep_copy(dummy)
      end

      nil
    end


    # saving default parameter
    # @return `next

    def new_cert_save_default
      @sav_adv_cri_ca = CaMgm.adv_cri_ca
      @sav_adv_ca = CaMgm.adv_ca
      @sav_adv_pathlen = CaMgm.adv_pathlen
      @sav_adv_pathlenValue = CaMgm.adv_pathlenValue

      @sav_adv_cri_distribution_point = CaMgm.adv_cri_distribution_point
      @sav_adv_distribution_point = CaMgm.adv_distribution_point

      @sav_adv_challenge_password = CaMgm.adv_challenge_password

      @sav_adv_cri_issuer_alt_name = CaMgm.adv_cri_issuer_alt_name
      @sav_adv_copy_issuer_alt_name = CaMgm.adv_copy_issuer_alt_name

      @sav_adv_cri_key_usage = CaMgm.adv_cri_key_usage
      @sav_adv_digitalSignature = CaMgm.adv_digitalSignature
      @sav_adv_nonRepudiation = CaMgm.adv_nonRepudiation
      @sav_adv_cRLSign = CaMgm.adv_cRLSign
      @sav_adv_keyEncipherment = CaMgm.adv_keyEncipherment
      @sav_adv_dataEncipherment = CaMgm.adv_dataEncipherment
      @sav_adv_encipherOnly = CaMgm.adv_encipherOnly
      @sav_adv_keyAgreement = CaMgm.adv_keyAgreement
      @sav_adv_keyCertSign = CaMgm.adv_keyCertSign
      @sav_adv_decipherOnly = CaMgm.adv_decipherOnly

      @sav_adv_cri_nsComment = CaMgm.adv_cri_nsComment
      @sav_adv_nsComment = CaMgm.adv_nsComment

      @sav_adv_cri_nsCertType = CaMgm.adv_cri_nsCertType
      @sav_adv_client = CaMgm.adv_client
      @sav_adv_server = CaMgm.adv_server
      @sav_adv_sslCA = CaMgm.adv_sslCA
      @sav_adv_email = CaMgm.adv_email
      @sav_adv_reserved = CaMgm.adv_reserved
      @sav_adv_emailCA = CaMgm.adv_emailCA
      @sav_adv_objsign = CaMgm.adv_objsign
      @sav_adv_objCA = CaMgm.adv_objCA

      @sav_adv_cri_nsSslServerName = CaMgm.adv_cri_nsSslServerName
      @sav_adv_nsSslServerName = CaMgm.adv_nsSslServerName

      @sav_adv_cri_subject_alt_name = CaMgm.adv_cri_subject_alt_name
      @sav_adv_copy_subject_alt_name = CaMgm.adv_copy_subject_alt_name

      @sav_adv_unstructured_name = CaMgm.adv_unstructured_name

      @sav_exp_cri_subjectKeyIdentifier = CaMgm.exp_cri_subjectKeyIdentifier
      @sav_exp_subjectKeyIdentifier = CaMgm.exp_subjectKeyIdentifier
      @sav_exp_cri_authorityKeyIdentifier = CaMgm.exp_cri_authorityKeyIdentifier
      @sav_exp_authorityKeyIdentifier = CaMgm.exp_authorityKeyIdentifier

      @sav_exp_cri_netscape_nsBaseUrl = CaMgm.exp_cri_netscape_nsBaseUrl
      @sav_exp_netscape_nsBaseUrl = CaMgm.exp_netscape_nsBaseUrl

      @sav_exp_cri_netscape_nsRevocationUrl = CaMgm.exp_cri_netscape_nsRevocationUrl(
      )
      @sav_exp_netscape_nsRevocationUrl = CaMgm.exp_netscape_nsRevocationUrl

      @sav_exp_cri_netscape_nsCaRevocationUrl = CaMgm.exp_cri_netscape_nsCaRevocationUrl(
      )
      @sav_exp_netscape_nsCaRevocationUrl = CaMgm.exp_netscape_nsCaRevocationUrl

      @sav_exp_cri_netscape_nsRenewalUrl = CaMgm.exp_cri_netscape_nsRenewalUrl
      @sav_exp_netscape_nsRenewalUrl = CaMgm.exp_netscape_nsRenewalUrl

      @sav_exp_cri_netscape_nsCaPolicyUrl = CaMgm.exp_cri_netscape_nsCaPolicyUrl
      @sav_exp_netscape_nsCaPolicyUrl = CaMgm.exp_netscape_nsCaPolicyUrl

      @sav_exp_cri_authorityInfoAccess = CaMgm.exp_cri_authorityInfoAccess
      @sav_exp_authorityInfoAccess = CaMgm.exp_authorityInfoAccess

      @sav_exp_cri_extendedKeyUsage = CaMgm.exp_cri_extendedKeyUsage
      @sav_exp_extendedKeyUsage = CaMgm.exp_extendedKeyUsage

      :next
    end

    #  "get" functions are used for setting already existing values or
    #  default values into the widgets.
    #
    #  "set" functions read the values from the widget and save these
    #  values to the global varibable ( defined in CaMgm.ycp )


    def get_advanced_basic_constaints
      Builtins.y2debug("calling get_advanced_basic_constaints")

      UI.ChangeWidget(Id(:id_adv_cri_ca), :Value, CaMgm.adv_cri_ca)
      if CaMgm.adv_ca == "CA:false"
        UI.ChangeWidget(Id(:id_adv_ca), :Value, :caFalse)
      end
      if CaMgm.adv_ca == "CA:true"
        UI.ChangeWidget(Id(:id_adv_ca), :Value, :caTrue)
      end
      UI.ChangeWidget(Id(:id_adv_ca), :Value, :none) if CaMgm.adv_ca == "none"
      UI.ChangeWidget(Id(:id_adv_pathlen), :Value, CaMgm.adv_pathlen)
      UI.ChangeWidget(Id(:id_adv_pathlenValue), :Value, CaMgm.adv_pathlenValue)
      UI.ChangeWidget(Id(:id_adv_pathlenValue), :Enabled, CaMgm.adv_pathlen)

      nil
    end
    def set_advanced_basic_constaints
      Builtins.y2debug("calling set_advanced_basic_constaints")
      error = ""

      CaMgm.adv_cri_ca = Convert.to_boolean(
        UI.QueryWidget(Id(:id_adv_cri_ca), :Value)
      )
      item = UI.QueryWidget(Id(:id_adv_ca), :Value)
      CaMgm.adv_ca = "CA:false" if item == :caFalse
      CaMgm.adv_ca = "CA:true" if item == :caTrue
      CaMgm.adv_ca = "none" if item == :none
      CaMgm.adv_pathlen = Convert.to_boolean(
        UI.QueryWidget(Id(:id_adv_pathlen), :Value)
      )
      CaMgm.adv_pathlenValue = Convert.to_integer(
        UI.QueryWidget(Id(:id_adv_pathlenValue), :Value)
      )

      error
    end
    def default_advanced_basic_constaints
      Builtins.y2debug("calling default_advanced_basic_constaints")

      CaMgm.adv_cri_ca = @sav_adv_cri_ca
      CaMgm.adv_ca = @sav_adv_ca
      CaMgm.adv_pathlen = @sav_adv_pathlen
      CaMgm.adv_pathlenValue = @sav_adv_pathlenValue
      resetAcceptRequestExtention("basicConstraints")

      nil
    end


    def get_advanced_CRL_distribution_point
      Builtins.y2debug("calling get_advanced_CRL_distribution_point")

      UI.ChangeWidget(
        Id(:id_adv_cri_distribution_point),
        :Value,
        CaMgm.adv_cri_distribution_point
      )
      UI.ChangeWidget(
        Id(:id_adv_distribution_point),
        :Value,
        CaMgm.adv_distribution_point
      )

      nil
    end
    def set_advanced_CRL_distribution_point
      Builtins.y2debug("calling set_advanced_CRL_distribution_point")
      error = ""

      CaMgm.adv_cri_distribution_point = Convert.to_boolean(
        UI.QueryWidget(Id(:id_adv_cri_distribution_point), :Value)
      )
      CaMgm.adv_distribution_point = Convert.to_string(
        UI.QueryWidget(Id(:id_adv_distribution_point), :Value)
      )

      error
    end
    def default_advanced_CRL_distribution_point
      Builtins.y2debug("calling default_advanced_CRL_distribution_point")

      CaMgm.adv_cri_distribution_point = @sav_adv_cri_distribution_point
      CaMgm.adv_distribution_point = @sav_adv_distribution_point
      resetAcceptRequestExtention("crlDistributionPoints")

      nil
    end


    def get_advanced_challenge_password
      Builtins.y2debug("calling get_advanced_challenge_password")

      UI.ChangeWidget(
        Id(:id_adv_challenge_password),
        :Value,
        CaMgm.adv_challenge_password
      )

      nil
    end
    def set_advanced_challenge_password
      Builtins.y2debug("calling set_advanced_challenge_password")
      error = ""

      CaMgm.adv_challenge_password = Convert.to_string(
        UI.QueryWidget(Id(:id_adv_challenge_password), :Value)
      )

      error
    end
    def default_advanced_challenge_password
      Builtins.y2debug("calling default_advanced_challenge_password")

      CaMgm.adv_challenge_password = @sav_adv_challenge_password

      nil
    end


    def get_advanced_issuer_alt_name
      Builtins.y2debug("calling get_advanced_issuer_alt_name")

      itemList = []
      i = 0
      Builtins.foreach(CaMgm.adv_issuer_alt_name_list) do |element|
        itemList = Builtins.add(
          itemList,
          Item(
            Id(i),
            Ops.get_string(element, "kind", ""),
            Ops.get_string(element, "name", "")
          )
        )
        i = Ops.add(i, 1)
      end

      UI.ChangeWidget(Id(:id_adv_issuer_alt_name), :Items, itemList)
      UI.ChangeWidget(
        Id(:id_adv_cri_issuer_alt_name),
        :Value,
        CaMgm.adv_cri_issuer_alt_name
      )
      UI.ChangeWidget(
        Id(:id_adv_copy_issuer_alt_name),
        :Value,
        CaMgm.adv_copy_issuer_alt_name
      )
      UI.ChangeWidget(
        Id(:id_adv_copy_issuer_alt_name),
        :Enabled,
        CaMgm.adv_copy_issuer_alt_name_enabled
      )

      nil
    end
    def set_advanced_issuer_alt_name
      Builtins.y2debug("calling set_advanced_issuer_alt_name")
      error = ""

      CaMgm.adv_cri_issuer_alt_name = Convert.to_boolean(
        UI.QueryWidget(Id(:id_adv_cri_issuer_alt_name), :Value)
      )
      CaMgm.adv_copy_issuer_alt_name = Convert.to_boolean(
        UI.QueryWidget(Id(:id_adv_copy_issuer_alt_name), :Value)
      )
      # The table widget will be filled in the add or delete callback

      error
    end
    def default_advanced_issuer_alt_name
      Builtins.y2debug("calling default_advanced_issuer_alt_name")

      CaMgm.adv_cri_issuer_alt_name = @sav_adv_cri_issuer_alt_name
      CaMgm.adv_copy_issuer_alt_name = @sav_adv_copy_issuer_alt_name
      resetAcceptRequestExtention("issuserAltName")

      nil
    end

    def add_advanced_issuer_alt_name
      Builtins.y2debug("Calling add_advanced_issuer_alt_name")

      UI.OpenDialog(Opt(:decorated), @issuer_box)
      UI.SetFocus(Id(:ok))
      while true
        ret = UI.UserInput
        if ret == :ok
          new_entry = {}
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
          CaMgm.adv_issuer_alt_name_list = Builtins.add(
            CaMgm.adv_issuer_alt_name_list,
            new_entry
          )
          break
        elsif ret == :cancel
          break
        end
      end

      UI.CloseDialog
      # restoring table
      get_advanced_issuer_alt_name

      nil
    end
    def delete_advanced_issuer_alt_name
      Builtins.y2debug("Calling delete_advanced_issuer_alt_name")

      current_item = Convert.to_integer(
        UI.QueryWidget(Id(:id_adv_issuer_alt_name), :CurrentItem)
      )
      table_item = Convert.to_term(
        UI.QueryWidget(Id(:id_adv_issuer_alt_name), term(:Item, current_item))
      )

      if table_item == nil
        Popup.Error(_("No item has been selected."))
        return
      end

      current_kind = Ops.get_string(table_item, 1, "")
      current_name = Ops.get_string(table_item, 2, "")

      if Popup.YesNoHeadline(
          # To translators: ContinueCancel Popup headline
          _("Delete"),
          # To translators: ContinueCancel Popup
          _("Really delete this entry?")
        )
        new_entry = {}
        dummy_map = []

        #finding entry in list
        Builtins.foreach(CaMgm.adv_issuer_alt_name_list) do |element|
          if Ops.get_string(element, "kind", "") != current_kind ||
              Ops.get_string(element, "name", "") != current_name
            dummy_map = Builtins.add(dummy_map, element)
          end
        end

        CaMgm.adv_issuer_alt_name_list = deep_copy(dummy_map)
      end

      # restoring table
      get_advanced_issuer_alt_name

      nil
    end
    def modify_advanced_issuer_alt_name
      Builtins.y2debug("Calling modify_advanced_issuer_alt_name")

      current_item = Convert.to_integer(
        UI.QueryWidget(Id(:id_adv_issuer_alt_name), :CurrentItem)
      )
      table_item = Convert.to_term(
        UI.QueryWidget(Id(:id_adv_issuer_alt_name), term(:Item, current_item))
      )

      if table_item == nil
        Popup.Error(_("No item has been selected."))
        return
      end

      current_kind = Ops.get_string(table_item, 1, "")
      current_name = Ops.get_string(table_item, 2, "")

      UI.OpenDialog(Opt(:decorated), @issuer_box)

      UI.ChangeWidget(Id(:name), :Value, current_name)
      UI.ChangeWidget(Id(:rb), :CurrentButton, current_kind)

      UI.SetFocus(Id(:ok))
      while true
        ret = UI.UserInput
        if ret == :ok
          new_entry = {}
          dummy_map = []
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

          #finding entry in list
          Builtins.foreach(CaMgm.adv_issuer_alt_name_list) do |element|
            if Ops.get_string(element, "kind", "") == current_kind &&
                Ops.get_string(element, "name", "") == current_name
              dummy_map = Builtins.add(dummy_map, new_entry)
            else
              dummy_map = Builtins.add(dummy_map, element)
            end
          end

          CaMgm.adv_issuer_alt_name_list = deep_copy(dummy_map)
          break
        elsif ret == :cancel
          break
        end
      end

      UI.CloseDialog
      # restoring table
      get_advanced_issuer_alt_name

      nil
    end


    def get_advanced_key_usage
      Builtins.y2debug("calling get_advanced_key_usage")

      UI.ChangeWidget(
        Id(:id_adv_cri_key_usage),
        :Value,
        CaMgm.adv_cri_key_usage
      )
      UI.ChangeWidget(Id(:digitalSignature), :Value, CaMgm.adv_digitalSignature)
      UI.ChangeWidget(Id(:nonRepudiation), :Value, CaMgm.adv_nonRepudiation)
      UI.ChangeWidget(Id(:cRLSign), :Value, CaMgm.adv_cRLSign)
      UI.ChangeWidget(Id(:keyEncipherment), :Value, CaMgm.adv_keyEncipherment)
      UI.ChangeWidget(Id(:dataEncipherment), :Value, CaMgm.adv_dataEncipherment)
      UI.ChangeWidget(Id(:encipherOnly), :Value, CaMgm.adv_encipherOnly)
      UI.ChangeWidget(Id(:keyAgreement), :Value, CaMgm.adv_keyAgreement)
      UI.ChangeWidget(Id(:keyCertSign), :Value, CaMgm.adv_keyCertSign)
      UI.ChangeWidget(Id(:decipherOnly), :Value, CaMgm.adv_decipherOnly)

      nil
    end
    def set_advanced_key_usage
      Builtins.y2debug("calling set_advanced_key_usage")
      error = ""

      CaMgm.adv_cri_key_usage = Convert.to_boolean(
        UI.QueryWidget(Id(:id_adv_cri_key_usage), :Value)
      )
      CaMgm.adv_digitalSignature = Convert.to_boolean(
        UI.QueryWidget(Id(:digitalSignature), :Value)
      )
      CaMgm.adv_nonRepudiation = Convert.to_boolean(
        UI.QueryWidget(Id(:nonRepudiation), :Value)
      )
      CaMgm.adv_cRLSign = Convert.to_boolean(
        UI.QueryWidget(Id(:cRLSign), :Value)
      )
      CaMgm.adv_keyEncipherment = Convert.to_boolean(
        UI.QueryWidget(Id(:keyEncipherment), :Value)
      )
      CaMgm.adv_dataEncipherment = Convert.to_boolean(
        UI.QueryWidget(Id(:dataEncipherment), :Value)
      )
      CaMgm.adv_encipherOnly = Convert.to_boolean(
        UI.QueryWidget(Id(:encipherOnly), :Value)
      )
      CaMgm.adv_keyAgreement = Convert.to_boolean(
        UI.QueryWidget(Id(:keyAgreement), :Value)
      )
      CaMgm.adv_keyCertSign = Convert.to_boolean(
        UI.QueryWidget(Id(:keyCertSign), :Value)
      )
      CaMgm.adv_decipherOnly = Convert.to_boolean(
        UI.QueryWidget(Id(:decipherOnly), :Value)
      )

      error
    end
    def default_advanced_key_usage
      Builtins.y2debug("calling default_advanced_key_usage")

      CaMgm.adv_cri_key_usage = @sav_adv_cri_key_usage
      CaMgm.adv_digitalSignature = @sav_adv_digitalSignature
      CaMgm.adv_nonRepudiation = @sav_adv_nonRepudiation
      CaMgm.adv_cRLSign = @sav_adv_cRLSign
      CaMgm.adv_keyEncipherment = @sav_adv_keyEncipherment
      CaMgm.adv_dataEncipherment = @sav_adv_dataEncipherment
      CaMgm.adv_encipherOnly = @sav_adv_encipherOnly
      CaMgm.adv_keyAgreement = @sav_adv_keyAgreement
      CaMgm.adv_keyCertSign = @sav_adv_keyCertSign
      CaMgm.adv_decipherOnly = @sav_adv_decipherOnly
      resetAcceptRequestExtention("keyUsage")

      nil
    end


    def get_advanced_netscape_nsComment
      Builtins.y2debug("calling get_advanced_netscape_nsComment")

      UI.ChangeWidget(
        Id(:id_adv_cri_nsComment),
        :Value,
        CaMgm.adv_cri_nsComment
      )
      UI.ChangeWidget(Id(:id_adv_nsComment), :Value, CaMgm.adv_nsComment)

      nil
    end
    def set_advanced_netscape_nsComment
      Builtins.y2debug("calling set_advanced_netscape_nsComment")
      error = ""

      CaMgm.adv_cri_nsComment = Convert.to_boolean(
        UI.QueryWidget(Id(:id_adv_cri_nsComment), :Value)
      )
      CaMgm.adv_nsComment = Convert.to_string(
        UI.QueryWidget(Id(:id_adv_nsComment), :Value)
      )

      error
    end
    def default_advanced_netscape_nsComment
      Builtins.y2debug("calling default_advanced_netscape_nsComment")

      CaMgm.adv_cri_nsComment = @sav_adv_cri_nsComment
      CaMgm.adv_nsComment = @sav_adv_nsComment
      resetAcceptRequestExtention("nsComment")

      nil
    end


    def get_advanced_netscape_nsCertType
      Builtins.y2debug("calling get_advanced_netscape_nsCertType")

      UI.ChangeWidget(
        Id(:id_adv_cri_nsCertType),
        :Value,
        CaMgm.adv_cri_nsCertType
      )
      UI.ChangeWidget(Id(:client), :Value, CaMgm.adv_client)
      UI.ChangeWidget(Id(:server), :Value, CaMgm.adv_server)
      UI.ChangeWidget(Id(:sslCA), :Value, CaMgm.adv_sslCA)
      UI.ChangeWidget(Id(:email), :Value, CaMgm.adv_email)
      UI.ChangeWidget(Id(:reserved), :Value, CaMgm.adv_reserved)
      UI.ChangeWidget(Id(:emailCA), :Value, CaMgm.adv_emailCA)
      UI.ChangeWidget(Id(:objsign), :Value, CaMgm.adv_objsign)
      UI.ChangeWidget(Id(:objCA), :Value, CaMgm.adv_objCA)

      nil
    end
    def set_advanced_netscape_nsCertType
      Builtins.y2debug("calling set_advanced_netscape_nsCertType")
      error = ""

      CaMgm.adv_cri_nsCertType = Convert.to_boolean(
        UI.QueryWidget(Id(:id_adv_cri_nsCertType), :Value)
      )
      CaMgm.adv_client = Convert.to_boolean(UI.QueryWidget(Id(:client), :Value))
      CaMgm.adv_server = Convert.to_boolean(UI.QueryWidget(Id(:server), :Value))
      CaMgm.adv_sslCA = Convert.to_boolean(UI.QueryWidget(Id(:sslCA), :Value))
      CaMgm.adv_email = Convert.to_boolean(UI.QueryWidget(Id(:email), :Value))
      CaMgm.adv_reserved = Convert.to_boolean(
        UI.QueryWidget(Id(:reserved), :Value)
      )
      CaMgm.adv_emailCA = Convert.to_boolean(
        UI.QueryWidget(Id(:emailCA), :Value)
      )
      CaMgm.adv_objsign = Convert.to_boolean(
        UI.QueryWidget(Id(:objsign), :Value)
      )
      CaMgm.adv_objCA = Convert.to_boolean(UI.QueryWidget(Id(:objCA), :Value))

      error
    end
    def default_advanced_netscape_nsCertType
      Builtins.y2debug("calling default_advanced_netscape_nsCertType")

      CaMgm.adv_cri_nsCertType = @sav_adv_cri_nsCertType
      CaMgm.adv_client = @sav_adv_client
      CaMgm.adv_server = @sav_adv_server
      CaMgm.adv_sslCA = @sav_adv_sslCA
      CaMgm.adv_email = @sav_adv_email
      CaMgm.adv_reserved = @sav_adv_reserved
      CaMgm.adv_emailCA = @sav_adv_emailCA
      CaMgm.adv_objsign = @sav_adv_objsign
      CaMgm.adv_objCA = @sav_adv_objCA

      resetAcceptRequestExtention("nsCertType")

      nil
    end


    def get_advanced_netscape_nsSslServerName
      Builtins.y2debug("calling get_advanced_netscape_nsSslServerName")

      UI.ChangeWidget(
        Id(:id_adv_cri_nsSslServerName),
        :Value,
        CaMgm.adv_cri_nsSslServerName
      )
      UI.ChangeWidget(
        Id(:id_adv_nsSslServerName),
        :Value,
        CaMgm.adv_nsSslServerName
      )

      nil
    end
    def set_advanced_netscape_nsSslServerName
      Builtins.y2debug("calling set_advanced_netscape_nsSslServerName")
      error = ""

      CaMgm.adv_cri_nsSslServerName = Convert.to_boolean(
        UI.QueryWidget(Id(:id_adv_cri_nsSslServerName), :Value)
      )
      CaMgm.adv_nsSslServerName = Convert.to_string(
        UI.QueryWidget(Id(:id_adv_nsSslServerName), :Value)
      )

      error
    end
    def default_advanced_netscape_nsSslServerName
      Builtins.y2debug("calling default_advanced_netscape_nsSslServerName")

      CaMgm.adv_cri_nsSslServerName = @sav_adv_cri_nsSslServerName
      CaMgm.adv_nsSslServerName = @sav_adv_nsSslServerName
      resetAcceptRequestExtention("nsSslServerName")

      nil
    end


    def get_advanced_subject_alt_name
      Builtins.y2debug("calling get_advanced_subject_alt_name")

      itemList = []
      i = 0
      Builtins.foreach(CaMgm.adv_subject_alt_name_list) do |element|
        itemList = Builtins.add(
          itemList,
          Item(
            Id(i),
            Ops.get_string(element, "kind", ""),
            Ops.get_string(element, "name", "")
          )
        )
        i = Ops.add(i, 1)
      end

      UI.ChangeWidget(Id(:id_adv_subject_alt_name), :Items, itemList)
      UI.ChangeWidget(
        Id(:id_adv_cri_subject_alt_name),
        :Value,
        CaMgm.adv_cri_subject_alt_name
      )
      UI.ChangeWidget(
        Id(:id_adv_copy_subject_alt_name),
        :Value,
        CaMgm.adv_copy_subject_alt_name
      )
      if Ops.less_or_equal(Builtins.size(CaMgm.emailList), 0)
        # Do not copy if there is no email address available
        UI.ChangeWidget(Id(:id_adv_copy_subject_alt_name), :Enabled, false)
      else
        UI.ChangeWidget(Id(:id_adv_copy_subject_alt_name), :Enabled, true)
      end

      nil
    end
    def set_advanced_subject_alt_name
      Builtins.y2debug("calling set_advanced_subject_alt_name")
      error = ""

      CaMgm.adv_cri_subject_alt_name = Convert.to_boolean(
        UI.QueryWidget(Id(:id_adv_cri_subject_alt_name), :Value)
      )
      CaMgm.adv_copy_subject_alt_name = Convert.to_boolean(
        UI.QueryWidget(Id(:id_adv_copy_subject_alt_name), :Value)
      )
      # The table widget will be filled in the add or delete callback

      if Ops.less_or_equal(Builtins.size(CaMgm.currentCA), 0)
        # is a root CA
        # If the own "Subject Alt Name" is defined, the copy into will be "Issuer Alt Name" is allowed.
        if CaMgm.adv_cri_subject_alt_name || CaMgm.adv_copy_subject_alt_name ||
            Ops.greater_than(Builtins.size(CaMgm.adv_subject_alt_name_list), 0)
          CaMgm.adv_copy_issuer_alt_name_enabled = true
        else
          CaMgm.adv_copy_issuer_alt_name_enabled = false
          CaMgm.adv_copy_issuer_alt_name = false
        end
      end

      error
    end
    def default_advanced_subject_alt_name
      Builtins.y2debug("calling default_advanced_subject_alt_name")

      CaMgm.adv_cri_subject_alt_name = @sav_adv_cri_subject_alt_name
      CaMgm.adv_copy_subject_alt_name = @sav_adv_copy_subject_alt_name
      resetAcceptRequestExtention("subjectAltName")

      nil
    end

    def add_advanced_subject_alt_name
      Builtins.y2debug("Calling add_advanced_subject_alt_name")

      UI.OpenDialog(Opt(:decorated), @subject_box)
      UI.SetFocus(Id(:ok))
      if !CaMgm.adv_subject_alt_name_show_email
        UI.ChangeWidget(Id("email"), :Enabled, false)
      else
        UI.ChangeWidget(Id("email"), :Enabled, true)
      end
      while true
        ret = UI.UserInput
        if ret == :ok
          new_entry = {}
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
          CaMgm.adv_subject_alt_name_list = Builtins.add(
            CaMgm.adv_subject_alt_name_list,
            new_entry
          )
          break
        elsif ret == :cancel
          break
        end
      end

      UI.CloseDialog
      # restoring table
      get_advanced_subject_alt_name

      nil
    end
    def delete_advanced_subject_alt_name
      Builtins.y2debug("Calling delete_advanced_subject_alt_name")

      current_item = Convert.to_integer(
        UI.QueryWidget(Id(:id_adv_subject_alt_name), :CurrentItem)
      )
      table_item = Convert.to_term(
        UI.QueryWidget(Id(:id_adv_subject_alt_name), term(:Item, current_item))
      )

      if table_item == nil
        Popup.Error(_("No item has been selected."))
        return
      end

      current_kind = Ops.get_string(table_item, 1, "")
      current_name = Ops.get_string(table_item, 2, "")

      if Popup.YesNoHeadline(
          # To translators: ContinueCancel Popup headline
          _("Delete"),
          # To translators: ContinueCancel Popup
          _("Really delete this entry?")
        )
        dummy_map = []

        #finding entry in list
        Builtins.foreach(CaMgm.adv_subject_alt_name_list) do |element|
          if Ops.get_string(element, "kind", "") != current_kind ||
              Ops.get_string(element, "name", "") != current_name
            dummy_map = Builtins.add(dummy_map, element)
          end
        end

        CaMgm.adv_subject_alt_name_list = deep_copy(dummy_map)
      end

      # restoring table
      get_advanced_subject_alt_name

      nil
    end
    def modify_advanced_subject_alt_name
      Builtins.y2debug("Calling modify_advanced_subject_alt_name")

      current_item = Convert.to_integer(
        UI.QueryWidget(Id(:id_adv_subject_alt_name), :CurrentItem)
      )
      table_item = Convert.to_term(
        UI.QueryWidget(Id(:id_adv_subject_alt_name), term(:Item, current_item))
      )

      if table_item == nil
        Popup.Error(_("No item has been selected."))
        return
      end

      current_kind = Ops.get_string(table_item, 1, "")
      current_name = Ops.get_string(table_item, 2, "")

      UI.OpenDialog(Opt(:decorated), @subject_box)

      UI.ChangeWidget(Id(:name), :Value, current_name)
      UI.ChangeWidget(Id(:rb), :CurrentButton, current_kind)

      UI.SetFocus(Id(:ok))
      while true
        ret = UI.UserInput
        if ret == :ok
          new_entry = {}
          dummy_map = []
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

          #finding entry in list
          Builtins.foreach(CaMgm.adv_subject_alt_name_list) do |element|
            if Ops.get_string(element, "kind", "") == current_kind &&
                Ops.get_string(element, "name", "") == current_name
              dummy_map = Builtins.add(dummy_map, new_entry)
            else
              dummy_map = Builtins.add(dummy_map, element)
            end
          end

          CaMgm.adv_subject_alt_name_list = deep_copy(dummy_map)
          break
        elsif ret == :cancel
          break
        end
      end

      UI.CloseDialog
      # restoring table
      get_advanced_subject_alt_name

      nil
    end


    def get_advanced_unstructured_name
      Builtins.y2debug("calling get_advanced_unstructured_name")

      UI.ChangeWidget(
        Id(:id_adv_unstructured_name),
        :Value,
        CaMgm.adv_unstructured_name
      )

      nil
    end
    def set_advanced_unstructured_name
      Builtins.y2debug("calling set_advanced_unstructured_name")
      error = ""

      CaMgm.adv_unstructured_name = Convert.to_string(
        UI.QueryWidget(Id(:id_adv_unstructured_name), :Value)
      )

      error
    end
    def default_advanced_unstructured_name
      Builtins.y2debug("calling default_advanced_unstructured_name")

      CaMgm.adv_unstructured_name = @sav_adv_unstructured_name

      nil
    end


    def get_expert_key_identifier
      Builtins.y2debug("calling get_expert_key_identifier")

      UI.ChangeWidget(
        Id(:id_exp_cri_subjectKeyIdentifier),
        :Value,
        CaMgm.exp_cri_subjectKeyIdentifier
      )
      UI.ChangeWidget(
        Id(:id_exp_subjectKeyIdentifier),
        :Value,
        CaMgm.exp_subjectKeyIdentifier
      )
      UI.ChangeWidget(
        Id(:id_exp_cri_authorityKeyIdentifier),
        :Value,
        CaMgm.exp_cri_authorityKeyIdentifier
      )
      UI.ChangeWidget(
        Id(:id_exp_authorityKeyIdentifier),
        :Value,
        CaMgm.exp_authorityKeyIdentifier
      )

      nil
    end
    def set_expert_key_identifier
      Builtins.y2debug("calling set_expert_key_identifier")
      error = ""

      CaMgm.exp_cri_subjectKeyIdentifier = Convert.to_boolean(
        UI.QueryWidget(Id(:id_exp_cri_subjectKeyIdentifier), :Value)
      )
      CaMgm.exp_subjectKeyIdentifier = Convert.to_string(
        UI.QueryWidget(Id(:id_exp_subjectKeyIdentifier), :Value)
      )
      CaMgm.exp_cri_authorityKeyIdentifier = Convert.to_boolean(
        UI.QueryWidget(Id(:id_exp_cri_authorityKeyIdentifier), :Value)
      )
      CaMgm.exp_authorityKeyIdentifier = Convert.to_string(
        UI.QueryWidget(Id(:id_exp_authorityKeyIdentifier), :Value)
      )

      error
    end
    def default_expert_key_identifier
      Builtins.y2debug("calling default_expert_key_identifier")

      CaMgm.exp_cri_subjectKeyIdentifier = @sav_exp_cri_subjectKeyIdentifier
      CaMgm.exp_subjectKeyIdentifier = @sav_exp_subjectKeyIdentifier
      CaMgm.exp_cri_authorityKeyIdentifier = @sav_exp_cri_authorityKeyIdentifier
      CaMgm.exp_authorityKeyIdentifier = @sav_exp_authorityKeyIdentifier
      resetAcceptRequestExtention("subjectKeyIdentifier")
      resetAcceptRequestExtention("authorityInfoAccess")

      nil
    end

    def get_expert_subject_key_identifier
      Builtins.y2debug("calling get_expert_subject_key_identifier")

      UI.ChangeWidget(
        Id(:id_exp_cri_subjectKeyIdentifier),
        :Value,
        CaMgm.exp_cri_subjectKeyIdentifier
      )
      UI.ChangeWidget(
        Id(:id_exp_subjectKeyIdentifier),
        :Value,
        CaMgm.exp_subjectKeyIdentifier
      )

      nil
    end
    def set_expert_subject_key_identifier
      Builtins.y2debug("calling set_expert_subject_key_identifier")
      error = ""

      CaMgm.exp_cri_subjectKeyIdentifier = Convert.to_boolean(
        UI.QueryWidget(Id(:id_exp_cri_subjectKeyIdentifier), :Value)
      )
      CaMgm.exp_subjectKeyIdentifier = Convert.to_string(
        UI.QueryWidget(Id(:id_exp_subjectKeyIdentifier), :Value)
      )

      error
    end
    def default_expert_subject_key_identifier
      Builtins.y2debug("calling default_expert_subject_key_identifier")

      CaMgm.exp_cri_subjectKeyIdentifier = @sav_exp_cri_subjectKeyIdentifier
      CaMgm.exp_subjectKeyIdentifier = @sav_exp_subjectKeyIdentifier
      resetAcceptRequestExtention("subjectKeyIdentifier")

      nil
    end

    def get_expert_netscape_nsBaseUrl
      Builtins.y2debug("calling get_expert_netscape_nsBaseUrl")

      UI.ChangeWidget(
        Id(:id_exp_cri_netscape_nsBaseUrl),
        :Value,
        CaMgm.exp_cri_netscape_nsBaseUrl
      )
      UI.ChangeWidget(
        Id(:id_exp_netscape_nsBaseUrl),
        :Value,
        CaMgm.exp_netscape_nsBaseUrl
      )

      nil
    end
    def set_expert_netscape_nsBaseUrl
      Builtins.y2debug("calling set_expert_netscape_nsBaseUrl")
      error = ""

      CaMgm.exp_cri_netscape_nsBaseUrl = Convert.to_boolean(
        UI.QueryWidget(Id(:id_exp_cri_netscape_nsBaseUrl), :Value)
      )
      CaMgm.exp_netscape_nsBaseUrl = Convert.to_string(
        UI.QueryWidget(Id(:id_exp_netscape_nsBaseUrl), :Value)
      )

      error
    end
    def default_expert_netscape_nsBaseUrl
      Builtins.y2debug("calling default_expert_netscape_nsBaseUrl")

      CaMgm.exp_cri_netscape_nsBaseUrl = @sav_exp_cri_netscape_nsBaseUrl
      CaMgm.exp_netscape_nsBaseUrl = @sav_exp_netscape_nsBaseUrl
      resetAcceptRequestExtention("nsBaseUrl")

      nil
    end


    def get_expert_netscape_nsRevocationUrl
      Builtins.y2debug("calling get_expert_netscape_nsRevocationUrl")

      UI.ChangeWidget(
        Id(:id_exp_cri_netscape_nsRevocationUrl),
        :Value,
        CaMgm.exp_cri_netscape_nsRevocationUrl
      )
      UI.ChangeWidget(
        Id(:id_exp_netscape_nsRevocationUrl),
        :Value,
        CaMgm.exp_netscape_nsRevocationUrl
      )

      nil
    end
    def set_expert_netscape_nsRevocationUrl
      Builtins.y2debug("calling set_expert_netscape_nsRevocationUrl")
      error = ""

      CaMgm.exp_cri_netscape_nsRevocationUrl = Convert.to_boolean(
        UI.QueryWidget(Id(:id_exp_cri_netscape_nsRevocationUrl), :Value)
      )
      CaMgm.exp_netscape_nsRevocationUrl = Convert.to_string(
        UI.QueryWidget(Id(:id_exp_netscape_nsRevocationUrl), :Value)
      )

      error
    end
    def default_expert_netscape_nsRevocationUrl
      Builtins.y2debug("calling default_expert_netscape_nsRevocationUrl")

      CaMgm.exp_cri_netscape_nsRevocationUrl = @sav_exp_cri_netscape_nsRevocationUrl
      CaMgm.exp_netscape_nsRevocationUrl = @sav_exp_netscape_nsRevocationUrl
      resetAcceptRequestExtention("nsRevocationUrl")

      nil
    end


    def get_expert_netscape_nsCaRevocationUrl
      Builtins.y2debug("calling get_expert_netscape_nsCaRevocationUrl")

      UI.ChangeWidget(
        Id(:id_exp_cri_netscape_nsCaRevocationUrl),
        :Value,
        CaMgm.exp_cri_netscape_nsCaRevocationUrl
      )
      UI.ChangeWidget(
        Id(:id_exp_netscape_nsCaRevocationUrl),
        :Value,
        CaMgm.exp_netscape_nsCaRevocationUrl
      )

      nil
    end
    def set_expert_netscape_nsCaRevocationUrl
      Builtins.y2debug("calling set_expert_netscape_nsCaRevocationUrl")
      error = ""

      CaMgm.exp_cri_netscape_nsCaRevocationUrl = Convert.to_boolean(
        UI.QueryWidget(Id(:id_exp_cri_netscape_nsCaRevocationUrl), :Value)
      )
      CaMgm.exp_netscape_nsCaRevocationUrl = Convert.to_string(
        UI.QueryWidget(Id(:id_exp_netscape_nsCaRevocationUrl), :Value)
      )

      error
    end
    def default_expert_netscape_nsCaRevocationUrl
      Builtins.y2debug("calling default_expert_netscape_nsCaRevocationUrl")

      CaMgm.exp_cri_netscape_nsCaRevocationUrl = @sav_exp_cri_netscape_nsCaRevocationUrl
      CaMgm.exp_netscape_nsCaRevocationUrl = @sav_exp_netscape_nsCaRevocationUrl
      resetAcceptRequestExtention("nsCaRevocationUrl")

      nil
    end


    def get_expert_netscape_nsRenewalUrl
      Builtins.y2debug("calling get_expert_netscape_nsRenewalUrl")

      UI.ChangeWidget(
        Id(:id_exp_cri_netscape_nsRenewalUrl),
        :Value,
        CaMgm.exp_cri_netscape_nsRenewalUrl
      )
      UI.ChangeWidget(
        Id(:id_exp_netscape_nsRenewalUrl),
        :Value,
        CaMgm.exp_netscape_nsRenewalUrl
      )

      nil
    end
    def set_expert_netscape_nsRenewalUrl
      Builtins.y2debug("calling set_expert_netscape_nsRenewalUrl")
      error = ""

      CaMgm.exp_cri_netscape_nsRenewalUrl = Convert.to_boolean(
        UI.QueryWidget(Id(:id_exp_cri_netscape_nsRenewalUrl), :Value)
      )
      CaMgm.exp_netscape_nsRenewalUrl = Convert.to_string(
        UI.QueryWidget(Id(:id_exp_netscape_nsRenewalUrl), :Value)
      )

      error
    end
    def default_expert_netscape_nsRenewalUrl
      Builtins.y2debug("calling default_expert_netscape_nsRenewalUrl")

      CaMgm.exp_cri_netscape_nsRenewalUrl = @sav_exp_cri_netscape_nsRenewalUrl
      CaMgm.exp_netscape_nsRenewalUrl = @sav_exp_netscape_nsRenewalUrl
      resetAcceptRequestExtention("nsRenewalUrl")

      nil
    end


    def get_expert_netscape_nsCaPolicyUrl
      Builtins.y2debug("calling get_expert_netscape_nsCaPolicyUrl")

      UI.ChangeWidget(
        Id(:id_exp_cri_netscape_nsCaPolicyUrl),
        :Value,
        CaMgm.exp_cri_netscape_nsCaPolicyUrl
      )
      UI.ChangeWidget(
        Id(:id_exp_netscape_nsCaPolicyUrl),
        :Value,
        CaMgm.exp_netscape_nsCaPolicyUrl
      )

      nil
    end
    def set_expert_netscape_nsCaPolicyUrl
      Builtins.y2debug("calling set_expert_netscape_nsCaPolicyUrl")
      error = ""

      CaMgm.exp_cri_netscape_nsCaPolicyUrl = Convert.to_boolean(
        UI.QueryWidget(Id(:id_exp_cri_netscape_nsCaPolicyUrl), :Value)
      )
      CaMgm.exp_netscape_nsCaPolicyUrl = Convert.to_string(
        UI.QueryWidget(Id(:id_exp_netscape_nsCaPolicyUrl), :Value)
      )

      error
    end
    def default_expert_netscape_nsCaPolicyUrl
      Builtins.y2debug("calling default_expert_netscape_nsCaPolicyUrl")

      CaMgm.exp_cri_netscape_nsCaPolicyUrl = @sav_exp_cri_netscape_nsCaPolicyUrl
      CaMgm.exp_netscape_nsCaPolicyUrl = @sav_exp_netscape_nsCaPolicyUrl
      resetAcceptRequestExtention("nsCaPolicyUrl")

      nil
    end


    def get_expert_authorityInfoAccess
      Builtins.y2debug("calling get_expert_authorityInfoAccess")

      UI.ChangeWidget(
        Id(:id_exp_cri_authorityInfoAccess),
        :Value,
        CaMgm.exp_cri_authorityInfoAccess
      )
      UI.ChangeWidget(
        Id(:id_exp_authorityInfoAccess),
        :Value,
        CaMgm.exp_authorityInfoAccess
      )

      nil
    end
    def set_expert_authorityInfoAccess
      Builtins.y2debug("calling set_expert_authorityInfoAccess")
      error = ""

      CaMgm.exp_cri_authorityInfoAccess = Convert.to_boolean(
        UI.QueryWidget(Id(:id_exp_cri_authorityInfoAccess), :Value)
      )
      CaMgm.exp_authorityInfoAccess = Convert.to_string(
        UI.QueryWidget(Id(:id_exp_authorityInfoAccess), :Value)
      )

      error
    end
    def default_expert_authorityInfoAccess
      Builtins.y2debug("calling default_expert_authorityInfoAccess")

      CaMgm.exp_cri_authorityInfoAccess = @sav_exp_cri_authorityInfoAccess
      CaMgm.exp_authorityInfoAccess = @sav_exp_authorityInfoAccess
      resetAcceptRequestExtention("authorityInfoAccess")

      nil
    end


    def get_expert_extendedKeyUsage
      Builtins.y2debug("calling get_expert_extendedKeyUsage")

      UI.ChangeWidget(
        Id(:id_exp_cri_extendedKeyUsage),
        :Value,
        CaMgm.exp_cri_extendedKeyUsage
      )
      UI.ChangeWidget(
        Id(:id_exp_extendedKeyUsage),
        :Value,
        CaMgm.exp_extendedKeyUsage
      )

      nil
    end
    def set_expert_extendedKeyUsage
      Builtins.y2debug("calling set_expert_extendedKeyUsage")
      error = ""

      CaMgm.exp_cri_extendedKeyUsage = Convert.to_boolean(
        UI.QueryWidget(Id(:id_exp_cri_extendedKeyUsage), :Value)
      )
      CaMgm.exp_extendedKeyUsage = Convert.to_string(
        UI.QueryWidget(Id(:id_exp_extendedKeyUsage), :Value)
      )

      error
    end
    def default_expert_extendedKeyUsage
      Builtins.y2debug("calling default_expert_extendedKeyUsage")

      CaMgm.exp_cri_extendedKeyUsage = @sav_exp_cri_extendedKeyUsage
      CaMgm.exp_extendedKeyUsage = @sav_exp_extendedKeyUsage
      resetAcceptRequestExtention("extendedKeyUsage")

      nil
    end
  end
end
