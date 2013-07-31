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
#   new_cert_item.ycp
#
# Module:
#   CA Management
#
# Summary:
#   Items definition for advanced setting ( creating
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
  module CaManagementNewCertItemsInclude
    def initialize_ca_management_new_cert_items(include_target)
      Yast.import "UI"
      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/new_cert_callbacks.rb"

      @advanced_help = _(
        "<P>This frame shows further attributes and OpenSSL X509v3 extensions that can be set. If you are not familiar with these extensions, refer to the file /usr/share/doc/packages/openssl-doc/openssl.txt (package openssl-doc).</P>"
      )

      @expert_help = Ops.add(
        @advanced_help,
        _("<P>Wrong entries can make the certificate unusable.</P>")
      )

      # items for CA and Certificates
      @generalItemList = [
        Item(
          Id(:advanced),
          _("Advanced Settings"),
          true,
          [
            Item(Id(:advanced_basic_constaints), "Basic Constaints"),
            Item(Id(:advanced_CRL_distribution_point), "CRL Distribution Point"),
            Item(Id(:advanced_challenge_password), "Challenge Password"),
            Item(Id(:advanced_issuer_alt_name), "Issuer Alt Name"),
            Item(Id(:advanced_key_usage), "Key Usage"),
            Item(
              Id(:advanced_netscape_settings),
              "Netscape Settings",
              true,
              [
                Item(Id(:advanced_netscape_nsComment), "nsComment"),
                Item(Id(:advanced_netscape_nsCertType), "nsCertType"),
                Item(Id(:advanced_netscape_nsSslServerName), "nsSslServerName")
              ]
            ),
            Item(Id(:advanced_subject_alt_name), "Subject Alt Name"),
            Item(Id(:advanced_unstructured_name), "Unstructured Name")
          ]
        ),
        Item(
          Id(:expert),
          _("Expert Settings"),
          true,
          [
            Item(Id(:expert_key_identifier), "Key Identifier"),
            Item(
              Id(:expert_netscape_settings),
              "Netscape Settings",
              true,
              [
                Item(Id(:expert_netscape_nsBaseUrl), "nsBaseUrl"),
                Item(Id(:expert_netscape_nsRevocationUrl), "nsRevocationUrl"),
                Item(
                  Id(:expert_netscape_nsCaRevocationUrl),
                  "nsCaRevocationUrl"
                ),
                Item(Id(:expert_netscape_nsRenewalUrl), "nsRenewalUrl"),
                Item(Id(:expert_netscape_nsCaPolicyUrl), "nsCaPolicyUrl")
              ]
            ),
            Item(Id(:expert_authorityInfoAccess), "authorityInfoAccess"),
            Item(Id(:expert_extendedKeyUsage), "extendedKeyUsage")
          ]
        )
      ]

      # items for Requests
      @requestItemList = [
        Item(
          Id(:advanced),
          _("Advanced Settings"),
          true,
          [
            Item(Id(:advanced_basic_constaints), "Basic Constaints"),
            Item(Id(:advanced_challenge_password), "Challenge Password"),
            Item(Id(:advanced_key_usage), "Key Usage"),
            Item(
              Id(:advanced_netscape_settings),
              "Netscape Settings",
              true,
              [
                Item(Id(:advanced_netscape_nsComment), "nsComment"),
                Item(Id(:advanced_netscape_nsCertType), "nsCertType"),
                Item(Id(:advanced_netscape_nsSslServerName), "nsSslServerName")
              ]
            ),
            Item(Id(:advanced_subject_alt_name), "Subject Alt Name"),
            Item(Id(:advanced_unstructured_name), "Unstructured Name")
          ]
        ),
        Item(
          Id(:expert),
          _("Expert Settings"),
          true,
          [
            Item(Id(:expert_subject_key_identifier), "Subject Key Identifier"),
            Item(Id(:expert_extendedKeyUsage), "extendedKeyUsage")
          ]
        )
      ]


      @itemMap = {
        :advanced                          => {
          "name"   => _("Advanced Settings"),
          "widget" => RichText(Id(:id_advanced), @advanced_help)
        },
        :advanced_basic_constaints         => {
          "name"        => "Basic Constaints",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(Id(:id_adv_cri_ca), _("critical"), CaMgm.adv_cri_ca)
              ),
              VSpacing(1.5),
              HBox(
                HWeight(
                  1,
                  ComboBox(
                    Id(:id_adv_ca),
                    "CA",
                    [
                      Item(Id(:none), "none", CaMgm.adv_ca == "none"),
                      Item(Id(:caFalse), "CA:false", CaMgm.adv_ca == "CA:false"),
                      Item(Id(:caTrue), "CA:true", CaMgm.adv_ca == "CA:true")
                    ]
                  )
                )
              ),
              VSpacing(1.5),
              Left(
                CheckBox(
                  Id(:id_adv_pathlen),
                  Opt(:notify),
                  "Pathlength available",
                  CaMgm.adv_pathlen
                )
              ),
              HBox(
                HSpacing(3),
                IntField(
                  Id(:id_adv_pathlenValue),
                  "Pathlength",
                  1,
                  10000,
                  CaMgm.adv_pathlenValue
                )
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_advanced_basic_constaints },
          "getCallback" => lambda { get_advanced_basic_constaints },
          "setCallback" => lambda { set_advanced_basic_constaints }
        },
        :advanced_CRL_distribution_point   => {
          "name"        => "CRL Distribution Point",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_adv_cri_distribution_point),
                  _("critical"),
                  CaMgm.adv_cri_distribution_point
                )
              ),
              VSpacing(1.5),
              TextEntry(
                Id(:id_adv_distribution_point),
                "CRL Distribution Point",
                CaMgm.adv_distribution_point
              ),
              VSpacing(1.5)
            )
          ),
          "getCallback" => lambda { get_advanced_CRL_distribution_point },
          "setCallback" => lambda { set_advanced_CRL_distribution_point },
          "default"     => lambda { default_advanced_CRL_distribution_point }
        },
        :advanced_challenge_password       => {
          "name"        => "Challenge Password",
          "widget"      => Frame(
            "",
            VBox(
              VSpacing(1.5),
              TextEntry(
                Id(:id_adv_challenge_password),
                "Challenge Password",
                CaMgm.adv_challenge_password
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_advanced_challenge_password },
          "getCallback" => lambda { get_advanced_challenge_password },
          "setCallback" => lambda { set_advanced_challenge_password }
        },
        :advanced_issuer_alt_name          => {
          "name"           => "Issuer Alt Name",
          "widget"         => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_adv_cri_issuer_alt_name),
                  _("critical"),
                  CaMgm.adv_cri_issuer_alt_name
                )
              ),
              VSpacing(1.5),
              Left(
                CheckBox(
                  Id(:id_adv_copy_issuer_alt_name),
                  _("Copy Subject Alt Name from CA"),
                  CaMgm.adv_copy_issuer_alt_name
                )
              ),
              VSpacing(1.5),
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
                        PushButton(
                          Id(:delete),
                          Opt(:key_F5),
                          Label.DeleteButton
                        )
                      )
                    ),
                    VStretch()
                  )
                )
              ),
              VSpacing(1.5)
            )
          ),
          "default"        => lambda { default_advanced_issuer_alt_name },
          "getCallback"    => lambda { get_advanced_issuer_alt_name },
          "setCallback"    => lambda { set_advanced_issuer_alt_name },
          "addCallback"    => lambda { add_advanced_issuer_alt_name },
          "deleteCallback" => lambda { delete_advanced_issuer_alt_name },
          "modifyCallback" => lambda { modify_advanced_issuer_alt_name }
        },
        :advanced_key_usage                => {
          "name"        => "Key Usage",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_adv_cri_key_usage),
                  _("critical"),
                  CaMgm.adv_cri_key_usage
                )
              ),
              VSpacing(1.5),
              HBox(
                HSpacing(1),
                Frame(
                  "Key Usage:",
                  HBox(
                    VBox(
                      Left(
                        CheckBox(
                          Id(:digitalSignature),
                          "digitalSignature",
                          CaMgm.adv_digitalSignature
                        )
                      ),
                      Left(
                        CheckBox(
                          Id(:nonRepudiation),
                          "nonRepudiation",
                          CaMgm.adv_nonRepudiation
                        )
                      ),
                      Left(CheckBox(Id(:cRLSign), "cRLSign", CaMgm.adv_cRLSign)),
                      Left(
                        CheckBox(
                          Id(:keyEncipherment),
                          "keyEncipherment",
                          CaMgm.adv_keyEncipherment
                        )
                      ),
                      Left(
                        CheckBox(
                          Id(:dataEncipherment),
                          "dataEncipherment",
                          CaMgm.adv_dataEncipherment
                        )
                      )
                    ),
                    VBox(
                      Left(
                        CheckBox(
                          Id(:encipherOnly),
                          "encipherOnly",
                          CaMgm.adv_encipherOnly
                        )
                      ),
                      Left(
                        CheckBox(
                          Id(:keyAgreement),
                          "keyAgreement",
                          CaMgm.adv_keyAgreement
                        )
                      ),
                      Left(
                        CheckBox(
                          Id(:keyCertSign),
                          "keyCertSign",
                          CaMgm.adv_keyCertSign
                        )
                      ),
                      Left(
                        CheckBox(
                          Id(:decipherOnly),
                          "decipherOnly",
                          CaMgm.adv_decipherOnly
                        )
                      ),
                      Label("")
                    )
                  )
                ),
                HSpacing(1)
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_advanced_key_usage },
          "getCallback" => lambda { get_advanced_key_usage },
          "setCallback" => lambda { set_advanced_key_usage }
        },
        :advanced_netscape_settings        => {
          "name"   => "Netscape Settings",
          "widget" => Empty()
        },
        :advanced_netscape_nsComment       => {
          "name"        => "nsComment",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_adv_cri_nsComment),
                  _("critical"),
                  CaMgm.adv_cri_nsComment
                )
              ),
              VSpacing(1.5),
              TextEntry(Id(:id_adv_nsComment), "nsComment", CaMgm.adv_nsComment),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_advanced_netscape_nsComment },
          "getCallback" => lambda { get_advanced_netscape_nsComment },
          "setCallback" => lambda { set_advanced_netscape_nsComment }
        },
        :advanced_netscape_nsCertType      => {
          "name"        => "nsCertType",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_adv_cri_nsCertType),
                  _("critical"),
                  CaMgm.adv_cri_nsCertType
                )
              ),
              VSpacing(1.5),
              HBox(
                HSpacing(1),
                Frame(
                  "nsCertTyp:",
                  HBox(
                    VBox(
                      Left(CheckBox(Id(:client), "client", CaMgm.adv_client)),
                      Left(CheckBox(Id(:server), "server", CaMgm.adv_server)),
                      Left(CheckBox(Id(:sslCA), "sslCA", CaMgm.adv_sslCA)),
                      Left(CheckBox(Id(:email), "email", CaMgm.adv_email))
                    ),
                    VBox(
                      Left(
                        CheckBox(Id(:reserved), "reserved", CaMgm.adv_reserved)
                      ),
                      Left(CheckBox(Id(:emailCA), "emailCA", CaMgm.adv_emailCA)),
                      Left(CheckBox(Id(:objsign), "objsign", CaMgm.adv_objsign)),
                      Left(CheckBox(Id(:objCA), "objCA", CaMgm.adv_objCA))
                    )
                  )
                ),
                HSpacing(1)
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_advanced_netscape_nsCertType },
          "getCallback" => lambda { get_advanced_netscape_nsCertType },
          "setCallback" => lambda { set_advanced_netscape_nsCertType }
        },
        :advanced_netscape_nsSslServerName => {
          "name"        => "nsSslServerName",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_adv_cri_nsSslServerName),
                  _("critical"),
                  CaMgm.adv_cri_nsSslServerName
                )
              ),
              VSpacing(1.5),
              TextEntry(
                Id(:id_adv_nsSslServerName),
                "nsSslServerName",
                CaMgm.adv_nsSslServerName
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_advanced_netscape_nsSslServerName },
          "getCallback" => lambda { get_advanced_netscape_nsSslServerName },
          "setCallback" => lambda { set_advanced_netscape_nsSslServerName }
        },
        :advanced_subject_alt_name         => {
          "name"           => "Subject Alt Name",
          "widget"         => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_adv_cri_subject_alt_name),
                  _("critical"),
                  CaMgm.adv_cri_subject_alt_name
                )
              ),
              VSpacing(1.5),
              Left(
                CheckBox(
                  Id(:id_adv_copy_subject_alt_name),
                  _("Copy Standard E-Mail Address"),
                  CaMgm.adv_copy_subject_alt_name
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
                        PushButton(Id(:modify), Opt(:key_F3), Label.EditButton)
                      )
                    ),
                    HBox(
                      HWeight(
                        1,
                        PushButton(
                          Id(:delete),
                          Opt(:key_F5),
                          Label.DeleteButton
                        )
                      )
                    ),
                    VStretch()
                  )
                )
              ),
              VSpacing(1.5)
            )
          ),
          "default"        => lambda { default_advanced_subject_alt_name },
          "getCallback"    => lambda { get_advanced_subject_alt_name },
          "setCallback"    => lambda { set_advanced_subject_alt_name },
          "addCallback"    => lambda { add_advanced_subject_alt_name },
          "deleteCallback" => lambda { delete_advanced_subject_alt_name },
          "modifyCallback" => lambda { modify_advanced_subject_alt_name }
        },
        :advanced_unstructured_name        => {
          "name"        => "Unstructured Name",
          "widget"      => Frame(
            "",
            VBox(
              VSpacing(1.5),
              TextEntry(
                Id(:id_adv_unstructured_name),
                "Unstructured Named",
                CaMgm.adv_unstructured_name
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_advanced_unstructured_name },
          "getCallback" => lambda { get_advanced_unstructured_name },
          "setCallback" => lambda { set_advanced_unstructured_name }
        },
        :expert                            => {
          "name"   => _("Expert Settings"),
          "widget" => RichText(Id(:id_expert), @expert_help)
        },
        :expert_key_identifier             => {
          "name"        => "Key Identifier",
          "widget"      => VBox(
            Frame(
              "",
              VBox(
                Left(
                  CheckBox(
                    Id(:id_exp_cri_subjectKeyIdentifier),
                    _("critical"),
                    CaMgm.exp_cri_subjectKeyIdentifier
                  )
                ),
                TextEntry(
                  Id(:id_exp_subjectKeyIdentifier),
                  "Subject Key Identifier",
                  CaMgm.exp_subjectKeyIdentifier
                )
              )
            ),
            VSpacing(1.5),
            Frame(
              "",
              VBox(
                Left(
                  CheckBox(
                    Id(:id_exp_cri_authorityKeyIdentifier),
                    _("critical"),
                    CaMgm.exp_cri_authorityKeyIdentifier
                  )
                ),
                TextEntry(
                  Id(:id_exp_authorityKeyIdentifier),
                  "Authority Key Identifier",
                  CaMgm.exp_authorityKeyIdentifier
                ),
                VSpacing(1.5)
              )
            )
          ),
          "default"     => lambda { default_expert_key_identifier },
          "getCallback" => lambda { get_expert_key_identifier },
          "setCallback" => lambda { set_expert_key_identifier }
        },
        :expert_subject_key_identifier     => {
          "name"        => "Subject Key Identifier",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_exp_cri_subjectKeyIdentifier),
                  _("critical"),
                  CaMgm.exp_cri_subjectKeyIdentifier
                )
              ),
              TextEntry(
                Id(:id_exp_subjectKeyIdentifier),
                "Subject Key Identifier",
                CaMgm.exp_subjectKeyIdentifier
              )
            )
          ),
          "default"     => lambda { default_expert_subject_key_identifier },
          "getCallback" => lambda { get_expert_subject_key_identifier },
          "setCallback" => lambda { set_expert_subject_key_identifier }
        },
        :expert_netscape_settings          => {
          "name"   => "Netscape Settings",
          "widget" => Empty()
        },
        :expert_netscape_nsBaseUrl         => {
          "name"        => "nsBaseUrl",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_exp_cri_netscape_nsBaseUrl),
                  _("critical"),
                  CaMgm.exp_cri_netscape_nsBaseUrl
                )
              ),
              VSpacing(1.5),
              TextEntry(
                Id(:id_exp_netscape_nsBaseUrl),
                "nsBaseUrl",
                CaMgm.exp_netscape_nsBaseUrl
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_expert_netscape_nsBaseUrl },
          "getCallback" => lambda { get_expert_netscape_nsBaseUrl },
          "setCallback" => lambda { set_expert_netscape_nsBaseUrl }
        },
        :expert_netscape_nsRevocationUrl   => {
          "name"        => "nsRevocationUrl",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_exp_cri_netscape_nsRevocationUrl),
                  _("critical"),
                  CaMgm.exp_cri_netscape_nsRevocationUrl
                )
              ),
              VSpacing(1.5),
              TextEntry(
                Id(:id_exp_netscape_nsRevocationUrl),
                "nsRevocationUrl",
                CaMgm.exp_netscape_nsRevocationUrl
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_expert_netscape_nsRevocationUrl },
          "getCallback" => lambda { get_expert_netscape_nsRevocationUrl },
          "setCallback" => lambda { set_expert_netscape_nsRevocationUrl }
        },
        :expert_netscape_nsCaRevocationUrl => {
          "name"        => "nsCaRevocationUrl",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_exp_cri_netscape_nsCaRevocationUrl),
                  _("critical"),
                  CaMgm.exp_cri_netscape_nsCaRevocationUrl
                )
              ),
              VSpacing(1.5),
              TextEntry(
                Id(:id_exp_netscape_nsCaRevocationUrl),
                "nsCaRevocationUrl",
                CaMgm.exp_netscape_nsCaRevocationUrl
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_expert_netscape_nsCaRevocationUrl },
          "getCallback" => lambda { get_expert_netscape_nsCaRevocationUrl },
          "setCallback" => lambda { set_expert_netscape_nsCaRevocationUrl }
        },
        :expert_netscape_nsRenewalUrl      => {
          "name"        => "nsRenewalUrl",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_exp_cri_netscape_nsRenewalUrl),
                  _("critical"),
                  CaMgm.exp_cri_netscape_nsRenewalUrl
                )
              ),
              VSpacing(1.5),
              TextEntry(
                Id(:id_exp_netscape_nsRenewalUrl),
                "nsRenewalUrl",
                CaMgm.exp_netscape_nsRenewalUrl
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_expert_netscape_nsRenewalUrl },
          "getCallback" => lambda { get_expert_netscape_nsRenewalUrl },
          "setCallback" => lambda { set_expert_netscape_nsRenewalUrl }
        },
        :expert_netscape_nsCaPolicyUrl     => {
          "name"        => "nsCaPolicyUrl",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_exp_cri_netscape_nsCaPolicyUrl),
                  _("critical"),
                  CaMgm.exp_cri_netscape_nsCaPolicyUrl
                )
              ),
              VSpacing(1.5),
              TextEntry(
                Id(:id_exp_netscape_nsCaPolicyUrl),
                "nsCaPolicyUrl",
                CaMgm.exp_netscape_nsCaPolicyUrl
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_expert_netscape_nsCaPolicyUrl },
          "getCallback" => lambda { get_expert_netscape_nsCaPolicyUrl },
          "setCallback" => lambda { set_expert_netscape_nsCaPolicyUrl }
        },
        :expert_authorityInfoAccess        => {
          "name"        => "authorityInfoAccess",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_exp_cri_authorityInfoAccess),
                  _("critical"),
                  CaMgm.exp_cri_authorityInfoAccess
                )
              ),
              VSpacing(1.5),
              TextEntry(
                Id(:id_exp_authorityInfoAccess),
                "authorityInfoAccess",
                CaMgm.exp_authorityInfoAccess
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_expert_authorityInfoAccess },
          "getCallback" => lambda { get_expert_authorityInfoAccess },
          "setCallback" => lambda { set_expert_authorityInfoAccess }
        },
        :expert_extendedKeyUsage           => {
          "name"        => "extendedKeyUsage",
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_exp_cri_extendedKeyUsage),
                  _("critical"),
                  CaMgm.exp_cri_extendedKeyUsage
                )
              ),
              VSpacing(1.5),
              TextEntry(
                Id(:id_exp_extendedKeyUsage),
                "extendedKeyUsage",
                CaMgm.exp_extendedKeyUsage
              ),
              VSpacing(1.5)
            )
          ),
          "default"     => lambda { default_expert_extendedKeyUsage },
          "getCallback" => lambda { get_expert_extendedKeyUsage },
          "setCallback" => lambda { set_expert_extendedKeyUsage }
        }
      }
    end
  end
end
