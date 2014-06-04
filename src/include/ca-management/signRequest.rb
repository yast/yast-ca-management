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
  module CaManagementSignRequestInclude
    def initialize_ca_management_signRequest(include_target)
      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/util.rb"
      Yast.include include_target, "ca-management/new_cert_read_write.rb"

      # Description of the current Request
      @currentRequestMap = {}
    end

    # getRequestDescription - description of a request
    # @param map of description, onlySubject
    # @return a string with the request description
    def getRequestDescription(requestMap, onlySubject)
      requestMap = deep_copy(requestMap)
      text = _("<p><b>Description</b></p>")
      if requestMap == nil
        showErrorCaManagement
        return _("\nRequest not found.\n")
      end
      text = Ops.add(text, "<pre>")
      dn = Ops.get_map(requestMap, "SUBJECT_HASH", {})
      if Ops.greater_than(Builtins.size(dn), 0)
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nCommon Name:        ")),
          Ops.get_string(Ops.get_list(dn, "CN", []), 0, "")
        )
        if Ops.greater_than(
            Builtins.size(Ops.get_string(requestMap, "date", "")),
            0
          )
          text = Ops.add(
            # Preformated Text: take care that all translations have the same length
            Ops.add(text, _("\ngeneration Time:    ")),
            Ops.get_string(requestMap, "date", "")
          )
        end
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nOrganization:       ")),
          Ops.get_string(Ops.get_list(dn, "O", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nLocation:           ")),
          Ops.get_string(Ops.get_list(dn, "L", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nState:              ")),
          Ops.get_string(Ops.get_list(dn, "ST", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nCountry:            ")),
          Ops.get_string(Ops.get_list(dn, "C", []), 0, "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nEMAIL:              ")),
          Ops.get_string(Ops.get_list(dn, "emailAddress", []), 0, "")
        )
      end
      if !onlySubject
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nIs CA:              ")),
          Ops.get_string(requestMap, "IS_CA", "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nKey Size:           ")),
          Ops.get_string(requestMap, "KEYSIZE", "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nVersion:            ")),
          Ops.get_string(requestMap, "VERSION", "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nalgo. of pub. Key : ")),
          Ops.get_string(requestMap, "PUBKEY_ALGORITHM", "")
        )
        text = Ops.add(
          # Preformated Text: take care that all translations have the same length
          Ops.add(text, _("\nalgo. of signature: ")),
          Ops.get_string(requestMap, "SIGNATURE_ALGORITHM", "")
        )
      end
      text = Ops.add(text, "</pre>")
      text
    end

    # Creates Request Extention items
    # @return a list items formated for a UI Multiselectionbox
    def createExtentionItem
      requestMap = Convert.to_map(
        YaPI::CaManagement.ReadRequest(
          {
            "caName"   => CaMgm.currentCA,
            "caPasswd" => getPassword(CaMgm.currentCA),
            "request"  => CaMgm.currentRequest,
            "type"     => "parsed"
          }
        )
      )

      opensslExtentions = Ops.get_map(requestMap, "OPENSSL_EXTENSIONS", {})
      result = []
      Builtins.foreach(CaMgm.requestExtentionValue) do |key, value|
        if key != "certificatePolicies"
          # this key will be ignored
          result = Builtins.add(
            result,
            Item(
              Id(key),
              Ops.add(
                Ops.add(Ops.get_string(value, "description", ""), ": "),
                Builtins.mergestring(
                  Convert.convert(
                    Ops.get(
                      opensslExtentions,
                      Ops.get_string(value, "description", ""),
                      []
                    ),
                    :from => "list",
                    :to   => "list <string>"
                  ),
                  " "
                )
              ),
              Builtins.contains(CaMgm.slectedRequestExtention, key)
            )
          )
        else
          Builtins.y2milestone("Ignoring certificatePolicies")
        end
      end
      deep_copy(result)
    end

    # Reset an accpetation of a RequestExtention
    # @param request extention
    # @return [void]
    def unsetRequestExtentions(extention)
      Builtins.y2milestone("Unset requestExtention %1", extention)
      if extention == "subjectKeyIdentifier"
        CaMgm.exp_cri_subjectKeyIdentifier = @sav_exp_cri_subjectKeyIdentifier
        CaMgm.exp_subjectKeyIdentifier = @sav_exp_subjectKeyIdentifier
      elsif extention == "subjectAltName"
        CaMgm.adv_cri_subject_alt_name = @sav_adv_cri_subject_alt_name
        CaMgm.adv_copy_subject_alt_name = @sav_adv_copy_subject_alt_name
      elsif extention == "basicConstraints"
        CaMgm.adv_pathlen = @sav_adv_pathlen
        CaMgm.adv_pathlenValue = @sav_adv_pathlenValue
        CaMgm.adv_cri_ca = @sav_adv_cri_ca
        CaMgm.adv_ca = @sav_adv_ca
      elsif extention == "keyUsage"
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
      elsif extention == "extendedKeyUsage"
        CaMgm.exp_cri_extendedKeyUsage = @sav_exp_cri_extendedKeyUsage
        CaMgm.exp_extendedKeyUsage = @sav_exp_extendedKeyUsage
      elsif extention == "nsComment"
        CaMgm.adv_cri_nsComment = @sav_adv_cri_nsComment
        CaMgm.adv_nsComment = @sav_adv_nsComment
      elsif extention == "authorityKeyIdentifier"
        CaMgm.exp_cri_authorityKeyIdentifier = @sav_exp_cri_authorityKeyIdentifier
        CaMgm.exp_authorityKeyIdentifier = @sav_exp_authorityKeyIdentifier
      elsif extention == "nsCertType"
        CaMgm.adv_cri_nsCertType = @sav_adv_cri_nsCertType
        CaMgm.adv_client = @sav_adv_client
        CaMgm.adv_server = @sav_adv_server
        CaMgm.adv_sslCA = @sav_adv_sslCA
        CaMgm.adv_email = @sav_adv_email
        CaMgm.adv_reserved = @sav_adv_reserved
        CaMgm.adv_emailCA = @sav_adv_emailCA
        CaMgm.adv_objsign = @sav_adv_objsign
        CaMgm.adv_objCA = @sav_adv_objCA
      elsif extention == "nsCaRevocationUrl"
        CaMgm.exp_cri_netscape_nsCaRevocationUrl = @sav_exp_cri_netscape_nsCaRevocationUrl
        CaMgm.exp_netscape_nsCaRevocationUrl = @sav_exp_netscape_nsCaRevocationUrl
      elsif extention == "nsCaPolicyUrl"
        CaMgm.exp_cri_netscape_nsCaPolicyUrl = @sav_exp_cri_netscape_nsCaPolicyUrl
        CaMgm.exp_netscape_nsCaPolicyUrl = @sav_exp_netscape_nsCaPolicyUrl
      elsif extention == "nsBaseUrl"
        CaMgm.exp_cri_netscape_nsBaseUrl = @sav_exp_cri_netscape_nsBaseUrl
        CaMgm.exp_netscape_nsBaseUrl = @sav_exp_netscape_nsBaseUrl
      elsif extention == "nsRenewalUrl"
        CaMgm.exp_cri_netscape_nsRenewalUrl = @sav_exp_cri_netscape_nsRenewalUrl
        CaMgm.exp_netscape_nsRenewalUrl = @sav_exp_netscape_nsRenewalUrl
      elsif extention == "nsRevocationUrl"
        CaMgm.exp_cri_netscape_nsRevocationUrl = @sav_exp_cri_netscape_nsRevocationUrl
        CaMgm.exp_netscape_nsRevocationUrl = @sav_exp_netscape_nsRevocationUrl
      elsif extention == "nsSslServerName"
        CaMgm.adv_cri_nsSslServerName = @sav_adv_cri_nsSslServerName
        CaMgm.adv_nsSslServerName = @sav_adv_nsSslServerName
      elsif extention == "issuserAltName"
        CaMgm.adv_cri_issuer_alt_name = @sav_adv_cri_issuer_alt_name
        CaMgm.adv_copy_subject_alt_name = @sav_adv_copy_subject_alt_name
      elsif extention == "crlDistributionPoints"
        CaMgm.adv_cri_distribution_point = @sav_adv_cri_distribution_point
        CaMgm.adv_distribution_point = @sav_adv_distribution_point
      elsif extention == "certificatePolicies"
        Builtins.y2milestone("certificatePolicies ignored")
      else
        Popup.Error(
          Builtins.sformat(_("Extension \"%1\" not found."), extention)
        )
      end

      nil
    end

    # The user has decide that given request extention
    # will be used. --> setting for signation
    # @param request extention
    # @return [void]
    def setRequestExtentions(extention)
      Builtins.y2milestone("Set requestExtention %1", extention)
      Builtins.y2milestone(
        "requestExtention %1",
        Ops.get(CaMgm.requestExtentionValue, extention, {})
      )

      extMap = Ops.get(CaMgm.requestExtentionValue, extention, {})

      if extention == "subjectKeyIdentifier"
        CaMgm.exp_cri_subjectKeyIdentifier = Ops.get_string(
          extMap,
          "critical",
          "0"
        ) == "1"
        CaMgm.exp_subjectKeyIdentifier = ""
        counter = 0

        Builtins.foreach(Ops.get_list(extMap, "value", [])) do |entry|
          if counter == 0
            CaMgm.exp_subjectKeyIdentifier = Ops.add(
              CaMgm.exp_subjectKeyIdentifier,
              entry
            )
          else
            CaMgm.exp_subjectKeyIdentifier = Ops.add(
              Ops.add(CaMgm.exp_subjectKeyIdentifier, ","),
              entry
            )
          end
          counter = Ops.add(counter, 1)
        end
      elsif extention == "subjectAltName"
        CaMgm.adv_subject_alt_name_list = []
        CaMgm.adv_cri_subject_alt_name = Ops.get_string(extMap, "critical", "0") == "1"
        CaMgm.adv_copy_subject_alt_name = false

        Builtins.foreach(Ops.get_list(extMap, "value", [])) do |entry|
          new_entry = {}
          Ops.set(new_entry, "kind", Ops.get_string(entry, "type", ""))
          Ops.set(new_entry, "name", Ops.get_string(entry, "value", ""))
          CaMgm.adv_subject_alt_name_list = Builtins.add(
            CaMgm.adv_subject_alt_name_list,
            new_entry
          )
        end
      elsif extention == "basicConstraints"
        CaMgm.adv_cri_ca = Ops.get_string(extMap, "critical", "0") == "1"
        CaMgm.adv_ca = ""

        Builtins.foreach(Ops.get_list(extMap, "value", [])) do |entry|
          if Ops.get_string(entry, "value", "") == "false" ||
              Ops.get_string(entry, "value", "") == "FALSE"
            CaMgm.adv_ca = Ops.add(Ops.get_string(entry, "type", ""), ":false")
          else
            CaMgm.adv_ca = Ops.add(Ops.get_string(entry, "type", ""), ":true")
          end
        end
      elsif extention == "keyUsage"
        CaMgm.adv_cri_key_usage = Ops.get_string(extMap, "critical", "0") == "1"
        CaMgm.adv_digitalSignature = false
        CaMgm.adv_nonRepudiation = false
        CaMgm.adv_cRLSign = false
        CaMgm.adv_keyEncipherment = false
        CaMgm.adv_dataEncipherment = false
        CaMgm.adv_encipherOnly = false
        CaMgm.adv_keyAgreement = false
        CaMgm.adv_keyCertSign = false
        CaMgm.adv_decipherOnly = false

        Builtins.foreach(Ops.get_list(extMap, "value", [])) do |entry|
          if entry == "digitalSignature"
            CaMgm.adv_digitalSignature = true
          elsif entry == "nonRepudiation"
            CaMgm.adv_nonRepudiation = true
          elsif entry == "cRLSign"
            CaMgm.adv_cRLSign = true
          elsif entry == "keyEncipherment"
            CaMgm.adv_keyEncipherment = true
          elsif entry == "dataEncipherment"
            CaMgm.adv_dataEncipherment = true
          elsif entry == "encipherOnly"
            CaMgm.adv_encipherOnly = true
          elsif entry == "keyAgreement"
            CaMgm.adv_keyAgreement = true
          elsif entry == "keyCertSign"
            CaMgm.adv_keyCertSign = true
          elsif entry == "decipherOnly"
            CaMgm.adv_decipherOnly = true
          end
        end
      elsif extention == "extendedKeyUsage"
        CaMgm.exp_cri_extendedKeyUsage = Ops.get_string(extMap, "critical", "0") == "1"
        CaMgm.exp_extendedKeyUsage = ""

        counter = 0
        Builtins.foreach(Ops.get_list(extMap, "value", [])) do |entry|
          if entry == "TLS Web Server Authentication"
            entry = "serverAuth"
          elsif entry == "TLS Web Client Authentication"
            entry = "clientAuth"
          elsif entry == "Code signing"
            entry = "codeSigning"
          elsif entry == "E-mail Protection"
            entry = "emailProtection"
          elsif entry == "Time Stamping"
            entry = "timeStamping"
          elsif entry == "Microsoft Individual Code Signing"
            entry = "msCodeInd"
          elsif entry == "Microsoft Commercial Code Signing"
            entry = "msCodeCom"
          elsif entry == "Microsoft Trust List Signing"
            entry = "msCTLSign"
          elsif entry == "Microsoft Server Gated Crypto"
            entry = "msSGC"
          elsif entry == "Microsoft Encrypted File System"
            entry = "msEFS"
          elsif entry == "Netscape Server Gated Crypto"
            entry = "nsSGC"
          elsif entry == "Microsoft Smartcardlogin"
            entry = "msSmartcardLogin"
          end
          if counter == 0
            CaMgm.exp_extendedKeyUsage = Ops.add(
              CaMgm.exp_extendedKeyUsage,
              entry
            )
          else
            CaMgm.exp_extendedKeyUsage = Ops.add(
              Ops.add(CaMgm.exp_extendedKeyUsage, ","),
              entry
            )
          end
          counter = Ops.add(counter, 1)
        end
      elsif extention == "nsComment"
        CaMgm.adv_cri_nsComment = Ops.get_string(extMap, "critical", "0") == "1"
        CaMgm.adv_nsComment = Ops.get_string(extMap, "value", "")
      elsif extention == "authorityKeyIdentifier"
        CaMgm.exp_cri_authorityKeyIdentifier = Ops.get_string(
          extMap,
          "critical",
          "0"
        ) == "1"
        CaMgm.exp_authorityKeyIdentifier = ""

        counter = 0
        Builtins.foreach(Ops.get_list(extMap, "value", [])) do |entry|
          if counter == 0
            CaMgm.exp_authorityKeyIdentifier = Ops.add(
              Ops.add(
                Ops.add(
                  CaMgm.exp_authorityKeyIdentifier,
                  Ops.get_string(entry, "type", "")
                ),
                Ops.greater_than(
                  Builtins.size(Ops.get_string(entry, "value", "")),
                  0
                ) ? ":" : ""
              ),
              Ops.get_string(entry, "value", "")
            )
          else
            CaMgm.exp_authorityKeyIdentifier = Ops.add(
              Ops.add(
                Ops.add(
                  Ops.add(CaMgm.exp_authorityKeyIdentifier, ","),
                  Ops.get_string(entry, "type", "")
                ),
                Ops.greater_than(
                  Builtins.size(Ops.get_string(entry, "value", "")),
                  0
                ) ? ":" : ""
              ),
              Ops.get_string(entry, "value", "")
            )
          end
          counter = Ops.add(counter, 1)
        end
        CaMgm.exp_authorityKeyIdentifier = strip(
          CaMgm.exp_authorityKeyIdentifier
        )
      elsif extention == "nsCertType"
        CaMgm.adv_cri_nsCertType = Ops.get_string(extMap, "critical", "0") == "1"
        CaMgm.adv_client = false
        CaMgm.adv_server = false
        CaMgm.adv_sslCA = false
        CaMgm.adv_email = false
        CaMgm.adv_reserved = false
        CaMgm.adv_emailCA = false
        CaMgm.adv_objsign = false
        CaMgm.adv_objCA = false

        Builtins.foreach(Ops.get_list(extMap, "value", [])) do |entry|
          if entry == "client"
            CaMgm.adv_client = true
          elsif entry == "server"
            CaMgm.adv_server = true
          elsif entry == "sslCA"
            CaMgm.adv_sslCA = true
          elsif entry == "email"
            CaMgm.adv_email = true
          elsif entry == "reserved"
            CaMgm.adv_reserved = true
          elsif entry == "emailCA"
            CaMgm.adv_emailCA = true
          elsif entry == "objsign"
            CaMgm.adv_objsign = true
          elsif entry == "objCA"
            CaMgm.adv_objCA = true
          end
        end
      elsif extention == "nsCaRevocationUrl"
        CaMgm.exp_cri_netscape_nsCaRevocationUrl = Ops.get_string(
          extMap,
          "critical",
          "0"
        ) == "1"
        CaMgm.exp_netscape_nsCaRevocationUrl = Ops.get_string(
          extMap,
          "value",
          ""
        )
      elsif extention == "nsCaPolicyUrl"
        CaMgm.exp_cri_netscape_nsCaPolicyUrl = Ops.get_string(
          extMap,
          "critical",
          "0"
        ) == "1"
        CaMgm.exp_netscape_nsCaPolicyUrl = Ops.get_string(extMap, "value", "")
      elsif extention == "nsBaseUrl"
        CaMgm.exp_cri_netscape_nsBaseUrl = Ops.get_string(
          extMap,
          "critical",
          "0"
        ) == "1"
        CaMgm.exp_netscape_nsBaseUrl = Ops.get_string(extMap, "value", "")
      elsif extention == "nsRenewalUrl"
        CaMgm.exp_cri_netscape_nsRenewalUrl = Ops.get_string(
          extMap,
          "critical",
          "0"
        ) == "1"
        CaMgm.exp_netscape_nsRenewalUrl = Ops.get_string(extMap, "value", "")
      elsif extention == "nsRevocationUrl"
        CaMgm.exp_cri_netscape_nsRevocationUrl = Ops.get_string(
          extMap,
          "critical",
          "0"
        ) == "1"
        CaMgm.exp_netscape_nsRevocationUrl = Ops.get_string(extMap, "value", "")
      elsif extention == "nsSslServerName"
        CaMgm.adv_cri_nsSslServerName = Ops.get_string(extMap, "critical", "0") == "1"
        CaMgm.adv_nsSslServerName = Ops.get_string(extMap, "value", "")
      elsif extention == "issuserAltName"
        CaMgm.adv_issuer_alt_name_list = []
        CaMgm.adv_cri_issuer_alt_name = Ops.get_string(extMap, "critical", "0") == "1"
        CaMgm.adv_copy_subject_alt_name = false

        Builtins.foreach(Ops.get_list(extMap, "value", [])) do |entry|
          new_entry = {}
          Ops.set(new_entry, "kind", Ops.get_string(entry, "type", ""))
          Ops.set(new_entry, "name", Ops.get_string(entry, "value", ""))
          CaMgm.adv_issuer_alt_name_list = Builtins.add(
            CaMgm.adv_issuer_alt_name_list,
            new_entry
          )
        end
      elsif extention == "crlDistributionPoints"
        CaMgm.adv_cri_distribution_point = Ops.get_string(
          extMap,
          "critical",
          "0"
        ) == "1"
        CaMgm.adv_distribution_point = ""
        counter = 0

        Builtins.foreach(Ops.get_list(extMap, "value", [])) do |entry|
          if counter == 0
            CaMgm.adv_distribution_point = Ops.add(
              Ops.add(
                Ops.add(
                  CaMgm.adv_distribution_point,
                  Ops.get_string(entry, "type", "")
                ),
                Ops.greater_than(
                  Builtins.size(Ops.get_string(entry, "value", "")),
                  0
                ) ? ":" : ""
              ),
              Ops.get_string(entry, "value", "")
            )
          else
            CaMgm.adv_distribution_point = Ops.add(
              Ops.add(
                Ops.add(
                  Ops.add(CaMgm.adv_distribution_point, ","),
                  Ops.get_string(entry, "type", "")
                ),
                Ops.greater_than(
                  Builtins.size(Ops.get_string(entry, "value", "")),
                  0
                ) ? ":" : ""
              ),
              Ops.get_string(entry, "value", "")
            )
          end
          counter = Ops.add(counter, 1)
        end
      elsif extention == "certificatePolicies"
        Builtins.y2milestone("certificatePolicies ignored")
      else
        Popup.Error(
          Builtins.sformat(_("Extension \"%1\" not found."), extention)
        )
      end

      nil
    end

    # setExtentionValues - Accept special extention values
    # @param list of accepted extentions
    def setExtentionValues(acceptedExtentions)
      acceptedExtentions = deep_copy(acceptedExtentions)
      Builtins.foreach(acceptedExtentions) do |extention|
        # setting all accepted extentions
        setRequestExtentions(extention)
      end

      Builtins.foreach(CaMgm.slectedRequestExtention) do |extention|
        if !Builtins.contains(acceptedExtentions, extention)
          #set to defaults
          unsetRequestExtentions(extention)
        end
      end

      CaMgm.slectedRequestExtention = deep_copy(acceptedExtentions)

      nil
    end

    # Values initializing for creating a Request
    # @param [String] kind ("Client Request","Server Request","CA Request")
    # @return `next,`abort
    def signRequestInit(kind)
      @currentRequestMap = Convert.to_map(
        YaPI::CaManagement.ReadRequest(
          {
            "caName"   => CaMgm.currentCA,
            "caPasswd" => getPassword(CaMgm.currentCA),
            "request"  => CaMgm.currentRequest,
            "type"     => "extended"
          }
        )
      )
      Builtins.y2milestone(
        "ReadRequest(%1,%2): %3",
        CaMgm.currentCA,
        CaMgm.currentRequest,
        @currentRequestMap
      )
      if @currentRequestMap == nil
        showErrorCaManagement
        return :abort
      end

      CaMgm.slectedRequestExtention = []
      CaMgm.requestExtentionValue = {}
      CaMgm.requestKind = ""
      CaMgm.requestSubject = ""
      CaMgm.validPeriod = 30

      # IS CA ?
      if Ops.get_string(@currentRequestMap, "IS_CA", "") == "1"
        if kind != "CA Request"
          message = Builtins.sformat(
            _("This is a CA request. Really sign it as a %1?"),
            kind
          )
          return :abort if !Popup.YesNo(message)
        end
      else
        if kind == "CA Request"
          message = _(
            "This is not a CA request. Really sign it as a CA request?"
          )
          return :abort if !Popup.YesNo(message)
        end
      end

      if kind == "CA Request"
        new_cert_init("Sub CA")
        CaMgm.requestKind = "ca"
      elsif kind == "Server Request"
        new_cert_init("Server Certificate")
        CaMgm.requestKind = "server"
      elsif kind == "Client Request"
        new_cert_init("Client Certificate")
        CaMgm.requestKind = "client"
      end

      # Subject
      CaMgm.requestSubject = Ops.get_string(@currentRequestMap, "DN", "")

      # Filling up reqeust extentions
      opensslExtentions = Ops.get_map(
        @currentRequestMap,
        "OPENSSL_EXTENSIONS",
        {}
      )
      Builtins.foreach(opensslExtentions) do |key, value|
        if Builtins.contains(CaMgm.validRequestExtention, key)
          CaMgm.requestExtentionValue = Builtins.add(
            CaMgm.requestExtentionValue,
            key,
            value
          )
        else
          Popup.Error(Builtins.sformat(_("Extension \"%1\" not found."), key))
        end
      end

      new_cert_save_default

      :next
    end



    # Signing a request ( 1. step )
    # @param [String] kind ("Client Request","Server Request","CA Request")
    # @return `next, 'abort
    def signRequest1(kind)
      helptext = ""
      # help text 1/3
      helptext = _("<p>This frame shows the signing request.</p>")

      # help text 2/3
      helptext = Ops.add(
        helptext,
        _(
          "<p>The request has special request extensions, which you can accept.</p>"
        )
      )
      # help text 3/3
      helptext = Ops.add(
        helptext,
        _(
          "<p>If you reject these extensions, the default values are taken instead.</p>"
        )
      )

      contents = VBox(
        RichText(getRequestDescription(@currentRequestMap, true)),
        IntField(
          Id(:period),
          _("&Valid Period (days):"),
          1,
          10000,
          CaMgm.validPeriod
        ),
        MultiSelectionBox(
          Id(:extentions),
          _("Requested Extensions"),
          createExtentionItem
        )
      )

      Wizard.SetContents(
        Builtins.sformat(_("Sign Request as a %1 (Step 1/2)"), kind),
        contents,
        helptext,
        true,
        true
      )
      Wizard.RestoreNextButton
      Wizard.DisableBackButton
      UI.SetFocus(Id(:period))

      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)

        if ui == :next
          CaMgm.validPeriod = Convert.to_integer(
            UI.QueryWidget(Id(:period), :Value)
          )
          setExtentionValues(
            Convert.convert(
              UI.QueryWidget(Id(:extentions), :SelectedItems),
              :from => "any",
              :to   => "list <string>"
            )
          )
        end
      end until Builtins.contains([:next, :abort], ui)

      ui
    end


    # Signing request ( 2. step )
    # @param [String] kind ("Client Request","Server Request","CA Request")
    # @return `next, 'back, 'cancel, `advancedOptions
    def signRequest2(kind)
      i = 0
      nextLine = false

      # help text 1/2
      helptext = _(
        "<p>This frame gives an overview of all settings for the request that will be signed.</p>"
      )
      # help text 2/2
      helptext = Ops.add(
        helptext,
        _("<p>Click <b>Sign Request</b> to go on.</p>")
      )

      text = _("<p><b>Summary</b></p>")
      text = Ops.add(text, "<br><pre>")
      text = Ops.add(
        Ops.add(
          Ops.add(text, "Subject:                  "),
          CaMgm.requestSubject
        ),
        "\n"
      )
      text = Ops.add(
        Ops.add(
          Ops.add(
            Ops.add(text, "Valid Period:             "),
            CaMgm.validPeriod
          ),
          _(" days")
        ),
        "\n"
      )
      text = Ops.add(
        Ops.add(Ops.add(text, "<p>Basic Constaints:         "), CaMgm.adv_ca),
        CaMgm.adv_cri_ca ? _(" (critical)</p>") : "</p>"
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
      if Ops.greater_than(Builtins.size(CaMgm.exp_extendedKeyUsage), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "extendedKeyUsage:         "),
            CaMgm.exp_extendedKeyUsage
          ),
          CaMgm.exp_cri_extendedKeyUsage ? _(" (critical)\n") : "\n"
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
      if Ops.greater_than(Builtins.size(CaMgm.adv_nsSslServerName), 0)
        text = Ops.add(
          Ops.add(
            Ops.add(text, "nsSslServerName:          "),
            CaMgm.adv_nsSslServerName
          ),
          CaMgm.adv_cri_nsSslServerName ? _(" (critical)\n") : "\n"
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

      text = Ops.add(text, "</pre>")

      contents = VBox()
      contents = Builtins.add(contents, RichText(text))
      contents = Builtins.add(
        contents,
        Right(PushButton(Id(:edit), Opt(:key_F4), _("&Edit Request")))
      )

      # To translators: dialog label
      Wizard.SetContents(
        Builtins.sformat(_("Sign Request as a %1 (Step 2/2)"), kind),
        contents,
        helptext,
        true,
        true
      )
      Wizard.SetNextButton(:next, _("Sign Request"))

      ui = nil
      begin
        ui = Convert.to_symbol(UI.UserInput)

        if ui == :next
          #signing request
          if !cert_write("signRequest")
            showErrorCaManagement
            ui = :again
          else
            CaMgm.adv_subject_alt_name_show_email = false
            Popup.Message(_("The request has been signed."))
          end
        elsif ui == :edit
          CaMgm.adv_subject_alt_name_show_email = true
        end
      end until Builtins.contains([:back, :next, :abort, :edit], ui)

      ui
    end
  end
end
